/*
 * flow_table_bench.c
 *
 * Compare the legacy segmented binary-tree flow table with the segmented
 * open-addressing table used by ndpiReader.
 *
 * Copyright (C) 2011-26 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "reader_util.h"

#include <inttypes.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_FLOWS 50000
#define DEFAULT_SHARDS 512
#define DEFAULT_LOOKUP_FACTOR 8

static u_int64_t rng_state = UINT64_C(0x6a09e667f3bcc909);

static u_int64_t bench_rand(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static double bench_cpu_seconds(void) {
  struct timespec ts;

  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static void bench_fill_flow(struct ndpi_flow_info *flow, u_int32_t id) {
  memset(flow, 0, sizeof(*flow));

  flow->flow_id = id;
  flow->protocol = (id & 1) ? IPPROTO_TCP : IPPROTO_UDP;
  flow->vlan_id = (u_int16_t)(id & 7);
  flow->src_ip = htonl(0x0a000000U | (id & 0x00ffffffU));
  flow->dst_ip = htonl(0x14000000U | ((id * 2654435761U) & 0x00ffffffU));
  flow->src_port = htons((u_int16_t)(1024 + (id % 60000)));
  flow->dst_port = htons((id & 1) ? 443 : 53);
  flow->hashval = flow->protocol + ntohl(flow->src_ip) + ntohl(flow->dst_ip) +
    ntohs(flow->src_port) + ntohs(flow->dst_port);
}

static u_int32_t legacy_shard(const struct ndpi_flow_info *flow,
			      u_int32_t num_shards) {
  return flow->hashval % num_shards;
}

static inline int cmp_n32(uint32_t a, uint32_t b) {
  return a == b ? 0 : ntohl(a) < ntohl(b) ? -1 : 1;
}

static inline int cmp_n16(uint16_t a, uint16_t b) {
  return a == b ? 0 : ntohs(a) < ntohs(b) ? -1 : 1;
}

/* Same ordering as ndpi_workflow_node_cmp(), the legacy table comparator. */
static int legacy_flow_cmp(const void *a, const void *b) {
  const struct ndpi_flow_info *fa = (const struct ndpi_flow_info *)a;
  const struct ndpi_flow_info *fb = (const struct ndpi_flow_info *)b;
  int r;

  if(fa->hashval < fb->hashval) return -1;
  if(fa->hashval > fb->hashval) return 1;
  if(fa->vlan_id < fb->vlan_id) return -1;
  if(fa->vlan_id > fb->vlan_id) return 1;
  if(fa->protocol < fb->protocol) return -1;
  if(fa->protocol > fb->protocol) return 1;

  r = cmp_n32(fa->src_ip, fb->src_ip); if(r) return r;
  r = cmp_n16(fa->src_port, fb->src_port); if(r) return r;
  r = cmp_n32(fa->dst_ip, fb->dst_ip); if(r) return r;
  return cmp_n16(fa->dst_port, fb->dst_port);
}

static int legacy_lookup(const struct ndpi_flow_info *flow,
			 void **roots, u_int32_t num_shards) {
  struct ndpi_flow_info key = *flow;
  void *found;
  u_int32_t shard = legacy_shard(flow, num_shards);

  found = ndpi_tfind(&key, &roots[shard], legacy_flow_cmp);
  if(found == NULL) {
    key.src_ip = flow->dst_ip;
    key.src_port = flow->dst_port;
    key.dst_ip = flow->src_ip;
    key.dst_port = flow->src_port;
    found = ndpi_tfind(&key, &roots[shard], legacy_flow_cmp);
  }

  return found != NULL;
}

static void legacy_no_free(void *node) {
  (void)node;
}

static int bench_legacy(struct ndpi_flow_info *flows, u_int32_t num_flows,
			u_int32_t num_lookups, u_int32_t num_shards,
			u_int64_t *memory_bytes) {
  void **roots;
  double begin, end;
  volatile u_int64_t found = 0;

  roots = (void **)calloc(num_shards, sizeof(void *));
  if(roots == NULL)
    return -1;

  begin = bench_cpu_seconds();
  for(u_int32_t i = 0; i < num_flows; i++) {
    if(ndpi_tsearch(&flows[i], &roots[legacy_shard(&flows[i], num_shards)],
		    legacy_flow_cmp) == NULL) {
      free(roots);
      return -1;
    }
  }
  end = bench_cpu_seconds();

  printf("segmented_tree,%u,%u,%.6f,", num_flows, num_lookups, end - begin);

  begin = bench_cpu_seconds();
  for(u_int32_t i = 0; i < num_lookups; i++) {
    u_int32_t id = (u_int32_t)(bench_rand() % num_flows);
    found += legacy_lookup(&flows[id], roots, num_shards);
  }
  end = bench_cpu_seconds();

  *memory_bytes = (u_int64_t)num_shards * sizeof(void *) +
    (u_int64_t)num_flows * sizeof(struct ndpi_flow_info) +
    (u_int64_t)num_flows * (3 * sizeof(void *));

  for(u_int32_t i = 0; i < num_shards; i++)
    ndpi_tdestroy(roots[i], legacy_no_free);
  free(roots);

  if(found != num_lookups)
    return -1;

  printf("%.6f,%.0f,%.2f,%" PRIu64 ",n/a\n", end - begin,
	 (double)num_lookups / (end - begin),
	 (end - begin) * 1000000000.0 / (double)num_lookups,
	 *memory_bytes);
  return 0;
}

static int bench_open_addressing(struct ndpi_flow_info *flows, u_int32_t num_flows,
				 u_int32_t num_lookups, u_int32_t num_shards,
				 u_int64_t *memory_bytes, u_int64_t *probes) {
  struct ndpi_flow_table *table;
  struct ndpi_flow_table_stats stats;
  double begin, end;
  volatile u_int64_t found = 0;

  table = ndpi_flow_table_init(num_shards);
  if(table == NULL)
    return -1;

  begin = bench_cpu_seconds();
  for(u_int32_t i = 0; i < num_flows; i++) {
    if(ndpi_flow_table_insert(table, &flows[i]) != 0) {
      ndpi_flow_table_free(table, NULL);
      return -1;
    }
  }
  end = bench_cpu_seconds();

  printf("open_addressing,%u,%u,%.6f,", num_flows, num_lookups, end - begin);

  begin = bench_cpu_seconds();
  for(u_int32_t i = 0; i < num_lookups; i++) {
    u_int32_t id = (u_int32_t)(bench_rand() % num_flows);
    ndpi_flow_table_key key;
    struct ndpi_flow_info *flow = &flows[id];

    key.src_ip = flow->src_ip;
    key.dst_ip = flow->dst_ip;
    key.src_port = flow->src_port;
    key.dst_port = flow->dst_port;
    key.vlan_id = flow->vlan_id;
    key.protocol = flow->protocol;

    if(i & 1) {
      u_int32_t src_ip = key.src_ip;
      u_int16_t src_port = key.src_port;
      key.src_ip = key.dst_ip;
      key.src_port = key.dst_port;
      key.dst_ip = src_ip;
      key.dst_port = src_port;
    }

    found += ndpi_flow_table_find(table, &key) == flow;
  }
  end = bench_cpu_seconds();

  ndpi_flow_table_get_stats(table, &stats);
  *memory_bytes = stats.memory_bytes +
    (u_int64_t)num_flows * sizeof(struct ndpi_flow_info);
  *probes = stats.probes;

  ndpi_flow_table_free(table, NULL);

  if(found != num_lookups)
    return -1;

  printf("%.6f,%.0f,%.2f,%" PRIu64 ",%.2f\n", end - begin,
	 (double)num_lookups / (end - begin),
	 (end - begin) * 1000000000.0 / (double)num_lookups,
	 *memory_bytes, (double)stats.probes / (double)num_lookups);
  return 0;
}

static int verify_tables(u_int32_t num_flows, u_int32_t num_shards) {
  struct ndpi_flow_info *flows;
  struct ndpi_flow_table *table;
  void **roots;
  int rc = 0;

  flows = (struct ndpi_flow_info *)calloc(num_flows, sizeof(*flows));
  roots = (void **)calloc(num_shards, sizeof(void *));
  table = ndpi_flow_table_init(num_shards);
  if(flows == NULL || roots == NULL || table == NULL) {
    rc = -1;
    goto out;
  }

  for(u_int32_t i = 0; i < num_flows; i++) {
    bench_fill_flow(&flows[i], i);
    if(ndpi_tsearch(&flows[i], &roots[legacy_shard(&flows[i], num_shards)],
		    legacy_flow_cmp) == NULL ||
       ndpi_flow_table_insert(table, &flows[i]) != 0) {
      fprintf(stderr, "insert mismatch at flow %u\n", i);
      rc = -1;
      goto out;
    }
  }

  for(u_int32_t i = 0; i < num_flows * 8; i++) {
    u_int32_t id = (u_int32_t)(bench_rand() % num_flows);
    struct ndpi_flow_info key = flows[id];
    ndpi_flow_table_key table_key;
    int reverse = (int)(bench_rand() & 1);
    int legacy_found, table_found;

    if(reverse) {
      u_int32_t src_ip = key.src_ip;
      u_int16_t src_port = key.src_port;
      key.src_ip = key.dst_ip;
      key.src_port = key.dst_port;
      key.dst_ip = src_ip;
      key.dst_port = src_port;
    }

    legacy_found = legacy_lookup(&key, roots, num_shards);

    table_key.src_ip = key.src_ip;
    table_key.dst_ip = key.dst_ip;
    table_key.src_port = key.src_port;
    table_key.dst_port = key.dst_port;
    table_key.vlan_id = key.vlan_id;
    table_key.protocol = key.protocol;
    table_found = ndpi_flow_table_find(table, &table_key) == &flows[id];

    if(legacy_found != table_found) {
      fprintf(stderr, "lookup mismatch at flow %u (direction %d)\n", id, reverse);
      rc = -1;
      goto out;
    }
  }

  for(u_int32_t i = 0; i < num_flows; i += 3) {
    if(ndpi_flow_table_remove(table, &flows[i]) != 0 ||
       ndpi_flow_table_find(table, &(ndpi_flow_table_key){
	   .src_ip = flows[i].src_ip,
	   .dst_ip = flows[i].dst_ip,
	   .src_port = flows[i].src_port,
	   .dst_port = flows[i].dst_port,
	   .vlan_id = flows[i].vlan_id,
	   .protocol = flows[i].protocol}) != NULL) {
      fprintf(stderr, "tombstone lookup mismatch at flow %u\n", i);
      rc = -1;
      goto out;
    }
  }

  for(u_int32_t i = 0; i < num_flows; i++) {
    ndpi_flow_table_key key;

    if((i % 3) == 0)
      continue;

    key.src_ip = flows[i].dst_ip;
    key.dst_ip = flows[i].src_ip;
    key.src_port = flows[i].dst_port;
    key.dst_port = flows[i].src_port;
    key.vlan_id = flows[i].vlan_id;
    key.protocol = flows[i].protocol;

    if(ndpi_flow_table_find(table, &key) != &flows[i]) {
      fprintf(stderr, "post-removal lookup mismatch at flow %u\n", i);
      rc = -1;
      goto out;
    }
  }

out:
  if(table != NULL)
    ndpi_flow_table_free(table, NULL);
  if(roots != NULL) {
    for(u_int32_t i = 0; i < num_shards; i++)
      ndpi_tdestroy(roots[i], legacy_no_free);
    free(roots);
  }
  free(flows);

  if(rc == 0)
    printf("consistency: %u flows, random reverse lookups and tombstones OK\n",
	   num_flows);
  return rc;
}

int main(int argc, char **argv) {
  struct ndpi_flow_info *flows;
  u_int32_t num_flows = DEFAULT_FLOWS;
  u_int32_t num_shards = DEFAULT_SHARDS;
  u_int32_t num_lookups;
  u_int64_t legacy_memory = 0, table_memory = 0, probes = 0;
  int verify_only = 0;

  if(argc > 1 && strcmp(argv[1], "--verify") == 0) {
    verify_only = 1;
    if(argc > 2)
      num_flows = (u_int32_t)strtoul(argv[2], NULL, 0);
  } else if(argc > 1) {
    num_flows = (u_int32_t)strtoul(argv[1], NULL, 0);
  }

  if(argc > 2)
    num_lookups = (u_int32_t)strtoul(argv[2], NULL, 0);
  else
    num_lookups = num_flows * DEFAULT_LOOKUP_FACTOR;

  if(!verify_only && argc > 3)
    num_shards = (u_int32_t)strtoul(argv[3], NULL, 0);

  if(num_flows == 0 || num_shards == 0 || num_lookups == 0) {
    fprintf(stderr, "usage: %s [num_flows [num_lookups [num_shards]]]\n", argv[0]);
    fprintf(stderr, "       %s --verify\n", argv[0]);
    return 1;
  }

  if(verify_only)
    return verify_tables(num_flows, num_shards) == 0 ? 0 : 1;

  flows = (struct ndpi_flow_info *)calloc(num_flows, sizeof(*flows));
  if(flows == NULL) {
    fprintf(stderr, "unable to allocate %u flow records\n", num_flows);
    return 1;
  }

  for(u_int32_t i = 0; i < num_flows; i++)
    bench_fill_flow(&flows[i], i);

  printf("backend,flows,lookups,insert_cpu_sec,lookup_cpu_sec,pps,ns_per_lookup,memory_bytes,avg_probes\n");

  if(bench_legacy(flows, num_flows, num_lookups, num_shards, &legacy_memory) != 0) {
    fprintf(stderr, "legacy benchmark failed\n");
    free(flows);
    return 1;
  }

  if(bench_open_addressing(flows, num_flows, num_lookups, num_shards,
			   &table_memory, &probes) != 0) {
    fprintf(stderr, "open-addressing benchmark failed\n");
    free(flows);
    return 1;
  }

  free(flows);
  return 0;
}
