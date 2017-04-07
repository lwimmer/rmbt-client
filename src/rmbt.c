/*******************************************************************************
 * Copyright 2017 Leonhard Wimmer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

#include "rmbt.h"

#include <uuid.h>
#include <json.h>
#include <signal.h>

#include "rmbt_config.h"
#include "rmbt_helper.h"
#include "rmbt_token.h"
#include "rmbt_flow.h"
#include "rmbt_ssl.h"

#define MAX_TO_FREE 64

#define IS_JSON_NULL(x)	(json_object_get_type(x) == json_type_null)

static void *to_free[MAX_TO_FREE];
static uint_fast16_t to_free_cnt;

static void print_help(void) {
	fprintf(stderr, "==== rmbt %s ====\n"
			"command line arguments:\n\n"
			" -c     json config file; use \"-\" to read from stdin\n"
			" -b     local ip to bind\n"
			" -h     host to connect to\n"
			" -p     port to connect to\n"
			" -e     connect using SSL/TLS\n"
			" -t     token to use (either -t or -s is needed)\n"
			" -s     secret for token generation\n"
			" -f     number of flows\n"
			" -d     measurement duration for downlink\n"
			" -u     measurement duration for uplink\n"
			" -n     number of rtt_tcp_payloads\n\n"
			"Default config:\n"
			"%s\n", RMBT_VERSION, DEFAULT_CONFIG);
}

static void remember_to_free(void *ptr) {
	if (to_free_cnt >= MAX_TO_FREE)
		fail("to_free limit reached");
	to_free[to_free_cnt++] = ptr;
}

static void do_free(void) {
	for (uint_fast16_t i = 0; i < to_free_cnt; i++) {
		free(to_free[i]);
		to_free[i] = NULL;
	}
	to_free_cnt = 0;
}

static void my_json_get_string(char **dst, json_object *json, const char *key) {
	json_object *value;
	if (json_object_object_get_ex(json, key, &value) && !IS_JSON_NULL(value)) {
		int r = asprintf(dst, "%s", json_object_get_string(value));
		if (r == -1)
			fail("could not asprintf in my_json_get_string");
		remember_to_free(*dst);
	}
}

static void my_json_get_bool(bool *dst, json_object *json, const char *key) {
	json_object *value;
	if (json_object_object_get_ex(json, key, &value) && !IS_JSON_NULL(value))
		(*dst) = json_object_get_boolean(value);
}

static void my_json_get_int_fast16_t(int_fast16_t *dst, json_object *json, const char *key) {
	json_object *value;
	if (json_object_object_get_ex(json, key, &value) && !IS_JSON_NULL(value))
		(*dst) = json_object_get_int(value);
}

static void read_config(TestConfig *c, json_object *json) {
	my_json_get_string(&c->bind_ip, json, "cnf_bind_ip");
	my_json_get_string(&c->server_host, json, "cnf_server_host");
	my_json_get_string(&c->server_port, json, "cnf_server_port");
	my_json_get_bool(&c->encrypt, json, "cnf_encrypt");
	my_json_get_bool(&c->encrypt_debug, json, "cnf_encrypt_debug");
	my_json_get_string(&c->cipherlist, json, "cnf_cipherlist");
	my_json_get_string(&c->secret, json, "cnf_secret");
	my_json_get_string(&c->token, json, "cnf_token");

	int_fast16_t timeout_s = 0;
	my_json_get_int_fast16_t(&timeout_s, json, "cnf_timeout_s");
	if (timeout_s > 0)
		c->timeout_ms = (int) (timeout_s * 1000);

	my_json_get_int_fast16_t(&c->dl_num_flows, json, "cnf_dl_num_flows");
	my_json_get_int_fast16_t(&c->ul_num_flows, json, "cnf_ul_num_flows");
	my_json_get_int_fast16_t(&c->dl_duration_s, json, "cnf_dl_duration_s");
	my_json_get_int_fast16_t(&c->ul_duration_s, json, "cnf_ul_duration_s");
	my_json_get_int_fast16_t(&c->rtt_tcp_payload_num, json, "cnf_rtt_tcp_payload_num");
	my_json_get_int_fast16_t(&c->dl_pretest_duration_s, json, "cnf_dl_pretest_duration_s");
	my_json_get_int_fast16_t(&c->ul_pretest_duration_s, json, "cnf_ul_pretest_duration_s");
	my_json_get_int_fast16_t(&c->dl_wait_time_s, json, "cnf_dl_wait_time_s");
	my_json_get_int_fast16_t(&c->ul_wait_time_s, json, "cnf_ul_wait_time_s");

	my_json_get_string(&c->file_summary, json, "cnf_file_summary");
	my_json_get_string(&c->file_flows, json, "cnf_file_flows");
}

static char *read_stdin(void) {
	size_t size = 512, min = 128, len = 0;
	char *p, *input = malloc(size);

	while (!feof(stdin)) {
		if (size - len <= min) {
			size *= 2;
			p = realloc(input, size);
			if (p == NULL) {
				free(input);
				return NULL;
			}
			input = p;
		}
		size_t num_read = fread(input + len, 1, size - len - 1, stdin); /* -1: reserve space for '\0' */
		len += num_read;
	}
	*(input + len++) = '\0';
	return input;
}

int main(int argc, char **argv) {
	TestConfig config = { .token = 0 };

	struct sigaction action = { .sa_handler = SIG_IGN };
	if (sigaction(SIGPIPE, &action, NULL) != 0)
		fail("sigaction");

	json_object *default_json = json_tokener_parse(DEFAULT_CONFIG);
	if (default_json == NULL)
		fail("could not read default config");
	read_config(&config, default_json);
	json_object_put(default_json);

	json_object *add_to_result = NULL;
	json_object *json;
	char *input;
	int c, r;
	while ((c = getopt(argc, argv, "?c:b:h:p:et:s:f:d:u:n:v")) != -1)
		switch (c) {

		case 'c':
			if (strcmp("-", optarg) == 0) { /* read from stdin */
				input = read_stdin();
				if (input == NULL)
					fail("could not read config from stdin");
				json = json_tokener_parse(input);
				free(input);
			} else {
				json = json_object_from_file(optarg);
				if (json == NULL)
					fail("could not read config file '%s'", optarg);
			}
			read_config(&config, json);
			if (json_object_object_get_ex(json, "cnf_add_to_result", &add_to_result))
				json_object_get(add_to_result);
			json_object_put(json);
			break;
		case 'b':
			config.bind_ip = optarg;
			break;

		case 'h':
			config.server_host = optarg;
			break;

		case 'p':
			config.server_port = optarg;
			break;

		case 'e':
			config.encrypt = true;
			break;

		case 't':
			if (config.secret != NULL)
				fail("arguments -t and -s are mutually exclusive");
			config.token = optarg;
			break;

		case 's':
			if (config.token != NULL)
				fail("arguments -t and -s are mutually exclusive");
			config.secret = optarg;
			break;

		case 'f':
			r = sscanf(optarg, "%" PRIdFAST16, &config.dl_num_flows);
			if (r <= 0)
				fail("could not parse argument to -%c: %s", c, optarg);
			config.ul_num_flows = config.dl_num_flows;
			break;

		case 'd':
			r = sscanf(optarg, "%" PRIdFAST16, &config.dl_duration_s);
			if (r <= 0)
				fail("could not parse argument to -%c: %s", c, optarg);
			break;

		case 'u':
			r = sscanf(optarg, "%" PRIdFAST16, &config.ul_duration_s);
			if (r <= 0)
				fail("could not parse argument to -%c: %s", c, optarg);
			break;

		case 'n':
			r = sscanf(optarg, "%" PRIdFAST16, &config.rtt_tcp_payload_num);
			if (r <= 0)
				fail("could not parse argument to -%c: %s", c, optarg);
			break;

		case 'v':
			fprintf(stderr, "rmbt version: %s\n", RMBT_VERSION);
			return EXIT_SUCCESS;

		default:
		case '?':
			print_help();
			return EXIT_SUCCESS;
		}

	if (config.server_host == NULL)
		fail("host is required (either via config file or -h)");

	if (config.server_port == 0)
		fail("port is required (either via config file or -h)");

	if (config.secret == NULL && config.token == NULL)
		fail("either token or secret is required (either via config file, -s or -t)");

	char time_str[20];
	snprintf(time_str, sizeof(time_str), "%ld", time(NULL));

	if (config.token == NULL) {
		/* need to generate token */
		uuid_t uuid;
		uuid_generate_random(uuid);
		char uuid_str[37];
		uuid_unparse_lower(uuid, uuid_str);

		char hmac_str[EVP_MAX_MD_SIZE * 2];
		calc_token(config.secret, uuid_str, time_str, hmac_str, sizeof(hmac_str));

		int size = snprintf(config.token, 0, "%s_%s_%s", uuid_str, time_str, hmac_str);
		if (size < 0)
			fail("error while generating token");
		size++;
		config.token = malloc((size_t) size);
		remember_to_free(config.token);
		snprintf(config.token, (size_t) size, "%s_%s_%s", uuid_str, time_str, hmac_str);
	}

	char uuid_str[37];
	if (sscanf(config.token, "%36[0-9a-f-]", uuid_str) != 1)
		fail("could not get uuid from token");

	init_ssl(config.encrypt);

	fprintf(stderr, "=== rmbt %s starting ===\n", RMBT_VERSION);

	Result result = { .id_test = uuid_str };

	int_fast16_t num_threads = config.dl_num_flows;
	if (config.ul_num_flows > num_threads)
		num_threads = config.ul_num_flows;
	pthread_barrier_t barrier;
	pthread_barrier_init(&barrier, NULL, (unsigned int) num_threads);

	ThreadArg thread_arg[num_threads];
	FlowResult flow_results[num_threads];
	memset(flow_results, 0, sizeof(flow_results));

	result.time_start_s = time(NULL);

	struct timespec ts_zero;
	ts_fill(&ts_zero);

	for (int_fast16_t t = 0; t < num_threads; t++) {
		thread_arg[t].cfg = &config;
		thread_arg[t].barrier = &barrier;
		thread_arg[t].thread_num = t;
		thread_arg[t].ts_zero = &ts_zero;
		thread_arg[t].flow_result = &flow_results[t];
		thread_arg[t].do_log = t == 0;
		thread_arg[t].do_rtt_tcp_payload = t == 0;
		thread_arg[t].do_downlink = t < config.dl_num_flows;
		thread_arg[t].do_uplink = t < config.ul_num_flows;
		pthread_create(&thread_arg[t].thread, NULL, &run_test_thread_start, &thread_arg[t]);
	}

	for (int_fast16_t t = 0; t < num_threads; t++) {
		pthread_join(thread_arg[t].thread, NULL);
	}

	pthread_barrier_destroy(&barrier);

	result.time_end_s = time(NULL);

	calc_results(&result, flow_results, num_threads);

	fprintf(stderr, "dl_throughput_mbps = %.6f\n", result.dl_throughput_kbps / 1000);
	fprintf(stderr, "ul_throughput_mbps = %.6f\n", result.ul_throughput_kbps / 1000);

	json_object *result_json = collect_summary_results(&result);
	flatten_json_object_to_object(result_json, add_to_result);
	printf("%s\n", json_object_to_json_string_ext(result_json, JSON_C_TO_STRING_PRETTY));

	const char *replacements[] = { "id_test", result.id_test, "time", time_str };
	size_t num_replacements = sizeof(replacements) / sizeof(char*) / 2;

	char buf[512];
	if (config.file_summary != NULL) {
		bool ok = variable_subst(buf, sizeof(buf), config.file_summary, replacements, num_replacements);
		FILE *f = fopen(ok ? buf : config.file_summary, "w");
		if (f == NULL)
			perror("could not open file for result summary");
		else {
			fprintf(f, "%s\n", json_object_to_json_string_ext(result_json, JSON_C_TO_STRING_PLAIN));
			fclose(f);
		}
	}
	json_object_put(result_json);

	if (config.file_flows != NULL) {
		bool ok = variable_subst(buf, sizeof(buf), config.file_flows, replacements, num_replacements);
		FILE *f = fopen(ok ? buf : config.file_flows, "w");
		if (f == NULL)
			perror("could not open file for raw results");
		else {
			json_object *raw_result_json = collect_raw_results(&result, flow_results, num_threads);
			flatten_json_object_to_object(result_json, add_to_result);
			fprintf(f, "%s\n", json_object_to_json_string_ext(raw_result_json, JSON_C_TO_STRING_PLAIN));
			json_object_put(raw_result_json);
			fclose(f);
		}
	}

	if (add_to_result != NULL)
		json_object_put(add_to_result);

	shutdown_ssl();

	do_free_flow_results(flow_results, num_threads);
	do_free();

	fprintf(stderr, "Exiting.\n");
	return 0;
}
