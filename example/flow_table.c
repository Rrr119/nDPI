/*
 * flow_table.c
 *
 * Copyright (C) 2011-26 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "reader_util.h"

#include <string.h>

#define NDPI_FLOW_TABLE_INITIAL_CAPACITY 16
#define NDPI_FLOW_TABLE_LOAD_NUM 3
#define NDPI_FLOW_TABLE_LOAD_DEN 4

#define NDPI_FLOW_TOMBSTONE ((struct ndpi_flow_info *)(uintptr_t)1)

struct ndpi_flow_table_shard {
  struct ndpi_flow_info **slots;
  u_int32_t capacity;
  u_int32_t entries;
  u_int32_t tombstones;
};

struct ndpi_flow_table {
  struct ndpi_flow_table_shard *shards;
  u_int32_t num_shards;
  u_int64_t lookups;
  u_int64_t probes;
  u_int64_t inserts;
  u_int64_t resizes;
};

static u_int64_t ndpi_flow_table_mix64(u_int64_t x) {
  x ^= x >> 30;
  x *= UINT64_C(0xbf58476d1ce4e5b9);
  x ^= x >> 27;
  x *= UINT64_C(0x94d049bb133111eb);
  x ^= x >> 31;
  return x;
}

static u_int64_t ndpi_flow_table_hash(const ndpi_flow_table_key *key) {
  u_int64_t a = ((u_int64_t)key->src_ip << 16) | key->src_port;
  u_int64_t b = ((u_int64_t)key->dst_ip << 16) | key->dst_port;
  u_int64_t first, second;
  u_int64_t h;

  if(a <= b) {
    first = a, second = b;
  } else {
    first = b, second = a;
  }

  h = ndpi_flow_table_mix64(first);
  h ^= ndpi_flow_table_mix64(second + UINT64_C(0x9e3779b97f4a7c15));
  h ^= ndpi_flow_table_mix64(((u_int64_t)key->protocol << 16) | key->vlan_id);

  return ndpi_flow_table_mix64(h);
}

static void ndpi_flow_table_key_from_flow(const struct ndpi_flow_info *flow,
					  ndpi_flow_table_key *key) {
  key->src_ip = flow->src_ip;
  key->dst_ip = flow->dst_ip;
  key->src_port = flow->src_port;
  key->dst_port = flow->dst_port;
  key->vlan_id = flow->vlan_id;
  key->protocol = flow->protocol;
}

static int ndpi_flow_table_match(const struct ndpi_flow_info *flow,
				 const ndpi_flow_table_key *key) {
  if(flow->vlan_id != key->vlan_id || flow->protocol != key->protocol)
    return 0;

  if(flow->src_ip == key->src_ip && flow->src_port == key->src_port &&
     flow->dst_ip == key->dst_ip && flow->dst_port == key->dst_port)
    return 1;

  return flow->src_ip == key->dst_ip && flow->src_port == key->dst_port &&
    flow->dst_ip == key->src_ip && flow->dst_port == key->src_port;
}

static u_int32_t ndpi_flow_table_shard_idx(struct ndpi_flow_table *table,
					   u_int64_t hash) {
  return (u_int32_t)(hash % table->num_shards);
}

static u_int32_t ndpi_flow_table_slot_idx(u_int64_t hash,
					  u_int32_t capacity) {
  return (u_int32_t)((hash >> 32) & (capacity - 1));
}

static u_int32_t ndpi_flow_table_find_slot(struct ndpi_flow_table *table,
					   struct ndpi_flow_table_shard *shard,
					   const ndpi_flow_table_key *key,
					   u_int64_t hash) {
  u_int32_t idx, first_tombstone = UINT32_MAX;

  if(shard->capacity == 0)
    return UINT32_MAX;

  idx = ndpi_flow_table_slot_idx(hash, shard->capacity);

  for(u_int32_t step = 0; step < shard->capacity; step++) {
    struct ndpi_flow_info *entry = shard->slots[idx];

    table->probes++;

    if(entry == NULL)
      return first_tombstone != UINT32_MAX ? first_tombstone : idx;

    if(entry == NDPI_FLOW_TOMBSTONE) {
      if(first_tombstone == UINT32_MAX)
	first_tombstone = idx;
    } else if(ndpi_flow_table_match(entry, key)) {
      return idx;
    }

    idx = (idx + 1) & (shard->capacity - 1);
  }

  return first_tombstone;
}

static int ndpi_flow_table_resize_shard(struct ndpi_flow_table *table,
					struct ndpi_flow_table_shard *shard) {
  u_int32_t new_capacity = shard->capacity ?
    shard->capacity * 2 : NDPI_FLOW_TABLE_INITIAL_CAPACITY;
  struct ndpi_flow_info **new_slots;

  new_slots = (struct ndpi_flow_info **)ndpi_calloc(new_capacity,
						     sizeof(struct ndpi_flow_info *));
  if(new_slots == NULL)
    return -1;

  for(u_int32_t i = 0; i < shard->capacity; i++) {
    struct ndpi_flow_info *flow = shard->slots[i];

    if(flow != NULL && flow != NDPI_FLOW_TOMBSTONE) {
      ndpi_flow_table_key key;
      u_int64_t hash;
      u_int32_t idx;

      ndpi_flow_table_key_from_flow(flow, &key);
      hash = ndpi_flow_table_hash(&key);
      idx = ndpi_flow_table_slot_idx(hash, new_capacity);

      while(new_slots[idx] != NULL)
	idx = (idx + 1) & (new_capacity - 1);

      new_slots[idx] = flow;
    }
  }

  ndpi_free(shard->slots);
  shard->slots = new_slots;
  shard->capacity = new_capacity;
  shard->tombstones = 0;
  table->resizes++;

  return 0;
}

struct ndpi_flow_table *ndpi_flow_table_init(u_int32_t num_shards) {
  struct ndpi_flow_table *table;

  if(num_shards == 0)
    num_shards = 1;

  table = (struct ndpi_flow_table *)ndpi_calloc(1, sizeof(*table));
  if(table == NULL)
    return NULL;

  table->shards = (struct ndpi_flow_table_shard *)ndpi_calloc(num_shards,
							       sizeof(*table->shards));
  if(table->shards == NULL) {
    ndpi_free(table);
    return NULL;
  }

  table->num_shards = num_shards;

  return table;
}

void ndpi_flow_table_free(struct ndpi_flow_table *table,
			  void (*free_flow)(void *node)) {
  if(table == NULL)
    return;

  for(u_int32_t i = 0; i < table->num_shards; i++) {
    struct ndpi_flow_table_shard *shard = &table->shards[i];

    if(free_flow != NULL) {
      for(u_int32_t j = 0; j < shard->capacity; j++) {
	if(shard->slots[j] != NULL && shard->slots[j] != NDPI_FLOW_TOMBSTONE)
	  free_flow(shard->slots[j]);
      }
    }

    ndpi_free(shard->slots);
  }

  ndpi_free(table->shards);
  ndpi_free(table);
}

struct ndpi_flow_info *ndpi_flow_table_find(struct ndpi_flow_table *table,
					    const ndpi_flow_table_key *key) {
  u_int64_t hash;
  u_int32_t shard_idx, slot_idx;
  struct ndpi_flow_table_shard *shard;
  struct ndpi_flow_info *entry;

  if(table == NULL || key == NULL)
    return NULL;

  table->lookups++;
  hash = ndpi_flow_table_hash(key);
  shard_idx = ndpi_flow_table_shard_idx(table, hash);
  shard = &table->shards[shard_idx];
  slot_idx = ndpi_flow_table_find_slot(table, shard, key, hash);

  if(slot_idx == UINT32_MAX)
    return NULL;

  entry = shard->slots[slot_idx];
  return entry == NDPI_FLOW_TOMBSTONE ? NULL : entry;
}

int ndpi_flow_table_insert(struct ndpi_flow_table *table,
			   struct ndpi_flow_info *flow) {
  ndpi_flow_table_key key;
  u_int64_t hash;
  u_int32_t shard_idx, slot_idx;
  struct ndpi_flow_table_shard *shard;

  if(table == NULL || flow == NULL)
    return -1;

  ndpi_flow_table_key_from_flow(flow, &key);
  hash = ndpi_flow_table_hash(&key);
  shard_idx = ndpi_flow_table_shard_idx(table, hash);
  shard = &table->shards[shard_idx];

  if(shard->capacity == 0 ||
     (shard->entries + shard->tombstones + 1) * NDPI_FLOW_TABLE_LOAD_DEN >=
      shard->capacity * NDPI_FLOW_TABLE_LOAD_NUM) {
    if(ndpi_flow_table_resize_shard(table, shard) != 0)
      return -1;
  }

  slot_idx = ndpi_flow_table_find_slot(table, shard, &key, hash);
  if(slot_idx == UINT32_MAX)
    return -1;

  if(shard->slots[slot_idx] != NULL &&
     shard->slots[slot_idx] != NDPI_FLOW_TOMBSTONE)
    return -1;

  if(shard->slots[slot_idx] == NDPI_FLOW_TOMBSTONE)
    shard->tombstones--;

  shard->slots[slot_idx] = flow;
  shard->entries++;
  table->inserts++;

  return 0;
}

int ndpi_flow_table_remove(struct ndpi_flow_table *table,
			   struct ndpi_flow_info *flow) {
  ndpi_flow_table_key key;
  u_int64_t hash;
  u_int32_t shard_idx, slot_idx;
  struct ndpi_flow_table_shard *shard;

  if(table == NULL || flow == NULL)
    return -1;

  ndpi_flow_table_key_from_flow(flow, &key);
  hash = ndpi_flow_table_hash(&key);
  shard_idx = ndpi_flow_table_shard_idx(table, hash);
  shard = &table->shards[shard_idx];
  slot_idx = ndpi_flow_table_find_slot(table, shard, &key, hash);

  if(slot_idx == UINT32_MAX || shard->slots[slot_idx] != flow)
    return -1;

  shard->slots[slot_idx] = NDPI_FLOW_TOMBSTONE;
  shard->entries--;
  shard->tombstones++;

  return 0;
}

void ndpi_flow_table_walk_shard(struct ndpi_flow_table *table, u_int32_t shard_idx,
				ndpi_flow_table_walker walker, void *user_data) {
  struct ndpi_flow_table_shard *shard;

  if(table == NULL || walker == NULL || shard_idx >= table->num_shards)
    return;

  shard = &table->shards[shard_idx];

  for(u_int32_t i = 0; i < shard->capacity; i++) {
    struct ndpi_flow_info *flow = shard->slots[i];

    if(flow != NULL && flow != NDPI_FLOW_TOMBSTONE)
      walker(&flow, ndpi_leaf, 0, user_data);
  }
}

void ndpi_flow_table_walk(struct ndpi_flow_table *table,
			  ndpi_flow_table_walker walker, void *user_data) {
  if(table == NULL)
    return;

  for(u_int32_t i = 0; i < table->num_shards; i++)
    ndpi_flow_table_walk_shard(table, i, walker, user_data);
}

void ndpi_flow_table_get_stats(struct ndpi_flow_table *table,
			       struct ndpi_flow_table_stats *stats) {
  u_int64_t memory_bytes;
  u_int32_t entries = 0;

  if(stats == NULL)
    return;

  memset(stats, 0, sizeof(*stats));
  if(table == NULL)
    return;

  memory_bytes = sizeof(*table) + table->num_shards * sizeof(*table->shards);

  for(u_int32_t i = 0; i < table->num_shards; i++) {
    entries += table->shards[i].entries;
    memory_bytes += table->shards[i].capacity * sizeof(struct ndpi_flow_info *);
  }

  stats->lookups = table->lookups;
  stats->probes = table->probes;
  stats->inserts = table->inserts;
  stats->resizes = table->resizes;
  stats->memory_bytes = memory_bytes;
  stats->entries = entries;
  stats->shards = table->num_shards;
}
