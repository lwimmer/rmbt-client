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

#include "rmbt_stats.h"

#include <sys/utsname.h>

json_object *get_utsname(void) {
	struct utsname n;
	if (uname(&n) < 0)
		return NULL;
	json_object *ret = json_object_new_object();
	json_object_object_add(ret, "sysname", json_object_new_string(n.sysname));
	json_object_object_add(ret, "nodename", json_object_new_string(n.nodename));
	json_object_object_add(ret, "release", json_object_new_string(n.release));
	json_object_object_add(ret, "version", json_object_new_string(n.version));
	json_object_object_add(ret, "machine", json_object_new_string(n.machine));
	return ret;
}


#ifndef __linux__

/* tcp_info is available on FreeBSD and possibly others, but we do not support it currently */

#pragma GCC diagnostic push  // require GCC 4.6
#pragma GCC diagnostic ignored "-Wunused-parameter" // json_object_object_foreachC otherwise leads to warnings
json_object *read_tcp_info(int sfd) {
	return NULL;
}

void add_tcp_info(int sfd, json_object *array) {
	return;
}

void print_tcp_info(int sfd, FILE *f) {
	fprintf(f, "no tcp_info available (not linux)\n");
}
#pragma GCC diagnostic pop  // require GCC 4.6

#else

#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <netinet/in.h>

static json_object *tcp_info_to_json(struct tcp_info *i) {
	json_object *ret = json_object_new_object();

	json_object_object_add(ret, "tcpi_state", json_object_new_int(i->tcpi_state));
	json_object_object_add(ret, "tcpi_ca_state", json_object_new_int(i->tcpi_ca_state));
	json_object_object_add(ret, "tcpi_retransmits", json_object_new_int(i->tcpi_retransmits));
	json_object_object_add(ret, "tcpi_probes", json_object_new_int(i->tcpi_probes));
	json_object_object_add(ret, "tcpi_backoff", json_object_new_int(i->tcpi_backoff));
	json_object_object_add(ret, "tcpi_options", json_object_new_int(i->tcpi_options));
	json_object_object_add(ret, "tcpi_snd_wscale", json_object_new_int(i->tcpi_snd_wscale));
	json_object_object_add(ret, "tcpi_rcv_wscale", json_object_new_int(i->tcpi_rcv_wscale));

	json_object_object_add(ret, "tcpi_rto", json_object_new_int64(i->tcpi_rto));
	json_object_object_add(ret, "tcpi_ato", json_object_new_int64(i->tcpi_ato));
	json_object_object_add(ret, "tcpi_snd_mss", json_object_new_int64(i->tcpi_snd_mss));
	json_object_object_add(ret, "tcpi_rcv_mss", json_object_new_int64(i->tcpi_rcv_mss));

	json_object_object_add(ret, "tcpi_unacked", json_object_new_int64(i->tcpi_unacked));
	json_object_object_add(ret, "tcpi_sacked", json_object_new_int64(i->tcpi_sacked));
	json_object_object_add(ret, "tcpi_lost", json_object_new_int64(i->tcpi_lost));
	json_object_object_add(ret, "tcpi_retrans", json_object_new_int64(i->tcpi_retrans));
	json_object_object_add(ret, "tcpi_fackets", json_object_new_int64(i->tcpi_fackets));

	json_object_object_add(ret, "tcpi_last_data_sent", json_object_new_int64(i->tcpi_last_data_sent));
	json_object_object_add(ret, "tcpi_last_ack_sent", json_object_new_int64(i->tcpi_last_ack_sent));
	json_object_object_add(ret, "tcpi_last_data_recv", json_object_new_int64(i->tcpi_last_data_recv));
	json_object_object_add(ret, "tcpi_last_ack_recv", json_object_new_int64(i->tcpi_last_ack_recv));

	json_object_object_add(ret, "tcpi_pmtu", json_object_new_int64(i->tcpi_pmtu));
	json_object_object_add(ret, "tcpi_rcv_ssthresh", json_object_new_int64(i->tcpi_rcv_ssthresh));
	json_object_object_add(ret, "tcpi_rtt", json_object_new_int64(i->tcpi_rtt));
	json_object_object_add(ret, "tcpi_rttvar", json_object_new_int64(i->tcpi_rttvar));
	json_object_object_add(ret, "tcpi_snd_ssthresh", json_object_new_int64(i->tcpi_snd_ssthresh));
	json_object_object_add(ret, "tcpi_snd_cwnd", json_object_new_int64(i->tcpi_snd_cwnd));
	json_object_object_add(ret, "tcpi_advmss", json_object_new_int64(i->tcpi_advmss));
	json_object_object_add(ret, "tcpi_reordering", json_object_new_int64(i->tcpi_reordering));

	json_object_object_add(ret, "tcpi_rcv_rtt", json_object_new_int64(i->tcpi_rcv_rtt));
	json_object_object_add(ret, "tcpi_rcv_space", json_object_new_int64(i->tcpi_rcv_space));

	json_object_object_add(ret, "tcpi_total_retrans", json_object_new_int64(i->tcpi_total_retrans));

	json_object_object_add(ret, "tcpi_pacing_rate", json_object_new_int64((int64_t)i->tcpi_pacing_rate));
	json_object_object_add(ret, "tcpi_max_pacing_rate", json_object_new_int64((int64_t)i->tcpi_max_pacing_rate));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
	/* 0df48c26d8418c5c9fba63fac15b660d70ca2f1c */
	json_object_object_add(ret, "tcpi_bytes_acked", json_object_new_int64((int64_t)i->tcpi_bytes_acked));
	/* bdd1f9edacb5f5835d1e6276571bbbe5b88ded48 */
	json_object_object_add(ret, "tcpi_bytes_received", json_object_new_int64((int64_t)i->tcpi_bytes_received));
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	/* 2efd055c53c06b7e89c167c98069bab9afce7e59 */
	json_object_object_add(ret, "tcpi_segs_out", json_object_new_int64(i->tcpi_segs_out));
	json_object_object_add(ret, "tcpi_segs_in", json_object_new_int64(i->tcpi_segs_in));
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
	/* cd9b266095f422267bddbec88f9098b48ea548fc */
	json_object_object_add(ret, "tcpi_notsent_bytes", json_object_new_int64(i->tcpi_notsent_bytes));
	json_object_object_add(ret, "tcpi_min_rtt", json_object_new_int64(i->tcpi_min_rtt));

	/* a44d6eacdaf56f74fad699af7f4925a5f5ac0e7f */
	json_object_object_add(ret, "tcpi_data_segs_in", json_object_new_int64(i->tcpi_data_segs_in));
	json_object_object_add(ret, "tcpi_data_segs_out", json_object_new_int64(i->tcpi_data_segs_out));
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
	/* eb8329e0a04db0061f714f033b4454326ba147f4 */
	json_object_object_add(ret, "tcpi_delivery_rate", json_object_new_int64((int64_t)i->tcpi_delivery_rate));
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	/* efd90174167530c67a54273fd5d8369c87f9bd32 */
	json_object_object_add(ret, "tcpi_busy_time", json_object_new_int64((int64_t)i->tcpi_busy_time));
	json_object_object_add(ret, "tcpi_rwnd_limited", json_object_new_int64((int64_t)i->tcpi_rwnd_limited));
	json_object_object_add(ret, "tcpi_sndbuf_limited", json_object_new_int64((int64_t)i->tcpi_sndbuf_limited));
#endif

	return ret;
}

json_object *read_tcp_info(int sfd) {
	struct tcp_info info = { 0 };
	socklen_t info_len = sizeof(info);
	if (getsockopt(sfd, IPPROTO_TCP, TCP_INFO, &info, &info_len) != 0)
		return NULL;
	return tcp_info_to_json(&info);
}

void add_tcp_info(int sfd, json_object *array) {
	json_object_array_add(array, read_tcp_info(sfd));
}

void print_tcp_info(int sfd, FILE *f) {
	fprintf(f, "%s\n", json_object_to_json_string_ext(read_tcp_info(sfd), JSON_C_TO_STRING_PRETTY));
}

#endif /* __linux__ */

