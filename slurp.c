//
//  slurp.c
//
//  Public domain, do what you want with it,
//  though I'd certainly be interested to hear
//  what you're using it for. :)
//
//  Initial author: https://github.com/sigabrt/slurp
//  Modified by: https://github.com/scumola/slurp
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <oauth.h>
#include <curl/curl.h>
#include <time.h>
#include <pthread.h>

#define MS_TO_NS (1000000)

#define DATA_TIMEOUT (90)

typedef enum {
	ERROR_TYPE_HTTP,
	ERROR_TYPE_RATE_LIMITED,
	ERROR_TYPE_SOCKET,
} error_type;

struct idletimer {
	int lastdl;
	time_t idlestart;
};

void read_auth_keys(const char *filename, int bufsize, char *ckey, char *csecret, char *atok, char *atoksecret);
void config_curlopts(CURL *curl, const char *url, FILE *outfile, void *prog_data);
void reconnect_wait(error_type error);
int progress_callback(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow);
void timestamp(void);
void *slurp(void *);
void *watchdog(void *);

char *ckey, *csecret, *atok, *atoksecret;
pthread_t t_watchdog;
pthread_t t_slurper;
FILE *out;

void *watchdog (void *arg) {
    while(1) {
        fprintf(stderr, "****** PING ******\n");
        sleep(1);
    }
}

int main(int argc, const char *argv[]) {
    int error;

	if (argc == 3) {
		out = fopen(argv[2], "w");
	} else if (argc == 2) {
		out = stdout;
	} else {
		fprintf(stderr, "usage: %s keyfile [outfile]\n", argv[0]);
		return 0;
	}

	// These may be found on your twitter dev page, under "Applications"
	// You will need to create a new app if you haven't already
	// The four keys should be on separate lines in this order:
	int bufsize = 64;
	ckey = (char *)malloc(bufsize * sizeof(char));
    csecret = (char *)malloc(bufsize * sizeof(char));
    atok = (char *)malloc(bufsize * sizeof(char));
    atoksecret = (char *)malloc(bufsize * sizeof(char));
	read_auth_keys(argv[1], bufsize, ckey, csecret, atok, atoksecret);

	if (ckey == NULL || csecret == NULL || atok == NULL || atoksecret == NULL) {
		fprintf(stderr, "Couldn't read key file. Aborting...\n");
		free(ckey);
		free(csecret);
		free(atok);
		free(atoksecret);
		return 1;
	}

	error = pthread_create(&t_watchdog, NULL, watchdog, (void *)NULL);
    if (0 != error) {
        fprintf(stderr, "ERROR: Couldn't start slurp thread: %d\n", error);
    }

	error = pthread_create(&t_slurper, NULL, slurp, (void *)NULL);
    if (0 != error) {
        fprintf(stderr, "ERROR: Couldn't start slurp thread: %d\n", error);
    }

    error = pthread_join(t_slurper, NULL);

	free(ckey);
	free(csecret);
	free(atok);
	free(atoksecret);

	fclose(out);
	exit(0);
}

void *slurp (void *arg) {

	const char *url = "https://stream.twitter.com/1.1/statuses/sample.json";

	// Sign the URL with OAuth
	char *signedurl = oauth_sign_url2(url, NULL, OA_HMAC, "GET", ckey, csecret, atok, atoksecret);

	curl_global_init(CURL_GLOBAL_ALL);
	CURL *curl = curl_easy_init();

	struct idletimer timeout;
	timeout.lastdl = 1;
	timeout.idlestart = 0;

	config_curlopts(curl, signedurl, out, (void *)&timeout);

	int curlstatus, httpstatus;
	char reconnect = 1;
	while (reconnect) {
		curlstatus = curl_easy_perform(curl);
		switch (curlstatus) {
			case 0: // Twitter closed the connection
			    timestamp();
				fprintf(stderr, "Connection terminated. Attempting reconnect...\n");
				reconnect_wait(ERROR_TYPE_SOCKET);
				curl_easy_cleanup(curl);
				curl = curl_easy_init();

				// The signed URL contains a timestamp, so it needs to be
				// regenerated each time we reconnect or else we'll get a 401
				signedurl = oauth_sign_url2(url, NULL, OA_HMAC, "GET", ckey, csecret, atok, atoksecret);
				config_curlopts(curl, signedurl, out, (void *)&timeout);
				break;
			case CURLE_HTTP_RETURNED_ERROR:
				curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpstatus);
				switch (httpstatus) {
					case 401:
					case 403:
					case 404:
					case 406:
					case 413:
					case 416:
						// No reconnects with these errors
                        timestamp();
						fprintf(stderr, "Request failed with HTTP error %d. Aborting...\n", httpstatus);
						reconnect = 0;
						break;
					case 420:
                        timestamp();
						fprintf(stderr, "Received rate limiting response, attempting reconnect...\n");
						reconnect_wait(ERROR_TYPE_RATE_LIMITED);

						signedurl = oauth_sign_url2(url, NULL, OA_HMAC, "GET", ckey, csecret, atok, atoksecret);
						config_curlopts(curl, signedurl, out, (void *)&timeout);
						break;
					case 503:
                        timestamp();
						fprintf(stderr, "Received HTTP error %d, attempting reconnect...\n", httpstatus);
						reconnect_wait(ERROR_TYPE_HTTP);

						signedurl = oauth_sign_url2(url, NULL, OA_HMAC, "GET", ckey, csecret, atok, atoksecret);
						config_curlopts(curl, signedurl, out, (void *)&timeout);
						break;
					default:
                        timestamp();
						fprintf(stderr, "Unexpected HTTP error %d. Aborting...\n", httpstatus);
						reconnect = 0;
						break;
				}
				break;
			case CURLE_ABORTED_BY_CALLBACK:
                timestamp();
				fprintf(stderr, "Timeout, attempting reconnect...\n");
				reconnect_wait(ERROR_TYPE_SOCKET);

				signedurl = oauth_sign_url2(url, NULL, OA_HMAC, "GET", ckey, csecret, atok, atoksecret);
				config_curlopts(curl, signedurl, out, (void *)&timeout);
				break;
			default:
				// Probably a socket error, attempt reconnnect
                timestamp();
				fprintf(stderr, "Unexpected error, attempting reconnect...\n");
				reconnect_wait(ERROR_TYPE_SOCKET);

				curl_easy_cleanup(curl);
				curl = curl_easy_init();
				signedurl = oauth_sign_url2(url, NULL, OA_HMAC, "GET", ckey, csecret, atok, atoksecret);
				config_curlopts(curl, signedurl, out, (void *)&timeout);
				break;
		}
	}

	fprintf(stderr, "Cleaning up...\n");
	curl_easy_cleanup(curl);
	curl_global_cleanup();

    free(signedurl);

	return 0;
}

/* read_auth_keys
 * filename: The name of the text file containing
 * 		the keys
 * bufsize: The maximum number of characters to read per line
 * ckey: Consumer key, must be allocated already
 * csecret: Consumer secret, must be allocated already
 * atok: App token, must be allocated already
 * atoksecret: App token secret, must be allocated already
 */
void read_auth_keys(const char *filename, int bufsize,
		char *ckey, char *csecret, char *atok, char *atoksecret)
{
	FILE *file = fopen(filename, "r");

	if (fgets(ckey, bufsize, file) == NULL) {
		return;
	}
	ckey[strlen(ckey)-1] = '\0'; // Remove the newline

	if (fgets(csecret, bufsize, file) == NULL) {
		return;
	}
	csecret[strlen(csecret)-1] = '\0';

	if (fgets(atok, bufsize, file) == NULL) {
		return;
	}
	atok[strlen(atok)-1] = '\0';

	if (fgets(atoksecret, bufsize, file) == NULL) {
		return;
	}
	atoksecret[strlen(atoksecret)-1] = '\0';

	fclose(file);
}

/* config_curlopts
 * curl: cURL easy handle
 * url: URL of streaming endpoint
 * outfile: file stream for retrieved data
 * prog_data: data to send to progress callback function
 */
void config_curlopts(CURL *curl, const char *url, FILE *outfile, void *prog_data) {
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "tweetslurp/0.2");

	// libcurl will now fail on an HTTP error (>=400)
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);

	// If no data callback is specified, libcurl will
	// write data to stdout or the file in writedata
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)outfile);

	// noprogress must be set to 0 for a user-defined
	// progress method to be called
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);

	curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_callback);
	curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, (void *)prog_data);

    curl_easy_setopt(curl, CURLOPT_ENCODING, "gzip");
}

/* reconnect_wait
 * bool_httperror: whether this was an http error or
 * 		not (i.e. it was a socket error)
 */
void reconnect_wait(error_type error) {
	static int http_sleep_s = 5;
	static int rate_limit_sleep_s = 60;
	static long sock_sleep_ms = 250;

	struct timespec t;
	switch (error) {
		case ERROR_TYPE_HTTP:
			t.tv_sec = http_sleep_s;
			t.tv_nsec = 0;

			// As per the streaming endpoint guidelines, double the
			// delay until 320 seconds is reached
			http_sleep_s *= 2;
			if (http_sleep_s > 320) {
				http_sleep_s = 320;
			}
			break;
		case ERROR_TYPE_RATE_LIMITED:
			t.tv_sec = rate_limit_sleep_s;
			t.tv_nsec = 0;

			// As per the streaming endpoint guidelines, double the
			// delay
			rate_limit_sleep_s *= 2;
			break;
		case ERROR_TYPE_SOCKET:
			t.tv_sec = sock_sleep_ms / 1000;
			t.tv_nsec = (sock_sleep_ms % 1000) * MS_TO_NS;

			// As per the streaming endpoint guidelines, add 250ms
			// for each successive attempt until 16 seconds is reached
			sock_sleep_ms += 250;
			if (sock_sleep_ms > 16000) {
				sock_sleep_ms = 16000;
			}
			break;
		default:
			t.tv_sec = 0;
			t.tv_nsec = 0;
			break;
	}
	nanosleep(&t, NULL);
}

/* progress_callback
 * see libcURL docs for method sig details
 */
int progress_callback(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow) {
	struct idletimer *timeout;
	timeout = (struct idletimer *)clientp;

	if (dlnow == 0) { // No data was transferred this time...
		// ...but some was last time:
		if (timeout->lastdl != 0) {
			// so start the timer
			timeout->idlestart = time(NULL);
		}
		// ...and 1) the timer has been started, and
		// 2) we've hit the timeout:
		else if (timeout->idlestart != 0 && (time(NULL) - timeout->idlestart) > DATA_TIMEOUT) {
			// so we reset the timer and return a non-zero
			// value to abort the transfer
			timeout->lastdl = 1;
			timeout->idlestart = 0;
			return 1;
		}
	} else {
		// ...but we didn't last time:
		if (timeout->lastdl == 0) {
			// so reset the timer
			timeout->idlestart = 0;
		}
	}

	timeout->lastdl = dlnow;
	return 0;
}

void timestamp(void) {
    char            fmt[64], buf[64];
    struct timeval  tv;
    struct tm       *tm;

    gettimeofday(&tv, NULL);
    if((tm = localtime(&tv.tv_sec)) != NULL) {
        strftime(fmt, sizeof fmt, "%Y-%m-%d %H:%M:%S.%%06u %z", tm);
        snprintf(buf, sizeof buf, fmt, tv.tv_usec);
        fprintf(stderr, "%s ", buf);
    }
}
