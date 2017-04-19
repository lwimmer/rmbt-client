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

#ifndef SRC_RMBT_STATS_H_
#define SRC_RMBT_STATS_H_

#include "rmbt_common.h"

#include <stdatomic.h>

#include "rmbt_json.h"

/*
 * We use our own version of tcp_info, as we might run on a kernel that is more recent
 * than the headers we are compiling against.
 * The "introduced in" comments refer to git commit ids of the linux kernel sources.
 * */
struct rmbt_tcp_info {
	u_int8_t	tcpi_state;
	u_int8_t	tcpi_ca_state;
	u_int8_t	tcpi_retransmits;
	u_int8_t	tcpi_probes;
	u_int8_t	tcpi_backoff;
	u_int8_t	tcpi_options;
	u_int8_t	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
	/* next one introduced in eb8329e0a04db0061f714f033b4454326ba147f4 (4.9) */
	u_int8_t	tcpi_delivery_rate_app_limited:1;

	u_int32_t	tcpi_rto;
	u_int32_t	tcpi_ato;
	u_int32_t	tcpi_snd_mss;
	u_int32_t	tcpi_rcv_mss;

	u_int32_t	tcpi_unacked;
	u_int32_t	tcpi_sacked;
	u_int32_t	tcpi_lost;
	u_int32_t	tcpi_retrans;
	u_int32_t	tcpi_fackets;

	/* Times. */
	u_int32_t	tcpi_last_data_sent;
	u_int32_t	tcpi_last_ack_sent;
	u_int32_t	tcpi_last_data_recv;
	u_int32_t	tcpi_last_ack_recv;

	/* Metrics. */
	u_int32_t	tcpi_pmtu;
	u_int32_t	tcpi_rcv_ssthresh;
	u_int32_t	tcpi_rtt;
	u_int32_t	tcpi_rttvar;
	u_int32_t	tcpi_snd_ssthresh;
	u_int32_t	tcpi_snd_cwnd;
	u_int32_t	tcpi_advmss;
	u_int32_t	tcpi_reordering;

	u_int32_t	tcpi_rcv_rtt;
	u_int32_t	tcpi_rcv_space;

	u_int32_t	tcpi_total_retrans;

	u_int64_t	tcpi_pacing_rate;
	u_int64_t	tcpi_max_pacing_rate;
	/* introduced in 0df48c26d8418c5c9fba63fac15b660d70ca2f1c (4.1) */
	u_int64_t	tcpi_bytes_acked;
	/* introduced in bdd1f9edacb5f5835d1e6276571bbbe5b88ded48 (4.1) */
	u_int64_t	tcpi_bytes_received;
	/* introduced in 2efd055c53c06b7e89c167c98069bab9afce7e59 (4.2) */
	u_int32_t	tcpi_segs_out;
	u_int32_t	tcpi_segs_in;

	/* introduced in cd9b266095f422267bddbec88f9098b48ea548fc (4.6) */
	u_int32_t	tcpi_notsent_bytes;
	u_int32_t	tcpi_min_rtt;
	/* introduced in a44d6eacdaf56f74fad699af7f4925a5f5ac0e7f (4.6) */
	u_int32_t	tcpi_data_segs_in;
	u_int32_t	tcpi_data_segs_out;

	/* introduced in eb8329e0a04db0061f714f033b4454326ba147f4 (4.9) */
	u_int64_t	tcpi_delivery_rate;

	/* introduced in efd90174167530c67a54273fd5d8369c87f9bd32 (4.10) */
	u_int64_t	tcpi_busy_time;
	u_int64_t	tcpi_rwnd_limited;
	u_int64_t	tcpi_sndbuf_limited;
};

/* macro to check if specified member was actually returned by getsockopt
 * (i.e. kernel supports it) */
#define	IS_IN_RMBT_TCP_INFO(len, m)	(offsetof(struct rmbt_tcp_info, m) + sizeof(((struct rmbt_tcp_info *)0)->m) <= len)
#define JSON_ADD_OBJ_TCP_INFO(len, obj, m)	if (IS_IN_RMBT_TCP_INFO(len, m)) { \
		rmbt_json_add_int64(obj, #m, (int64_t)i->m); }
#define JSON_ADD_OBJ_TCP_INFO_BITFIELD(len, obj, m, next_memb)	\
		if (offsetof(struct rmbt_tcp_info, next_memb) <= len) { \
			rmbt_json_add_int64(obj, #m, (int64_t)i->m); }

typedef struct {
	int_fast64_t ts;
	socklen_t tcp_info_length;
	struct rmbt_tcp_info tcp_info;
} TcpInfoEntry;

typedef struct {
	int sfd;
	TcpInfoEntry *tcp_infos;
	size_t tcp_infos_size;
	size_t tcp_infos_length;
} StatsThreadEntry;

typedef struct {
	struct timespec *ts_zero;
	StatsThreadEntry *entries;
	size_t length;
} StatsThreadArg;

void get_uname(rmbt_json obj);

rmbt_json_array get_stats_as_json_array(StatsThreadArg* e);
void stats_thread_set_sfd(int_fast16_t tid, int sfd);
void *stats_thread_start(void *arg) __attribute__ ((noreturn));

#endif /* SRC_RMBT_STATS_H_ */
