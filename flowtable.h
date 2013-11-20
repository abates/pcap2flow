


#ifndef __FLOWTABLE_H__
#define __FLOWTABLE_H__

#include "hash.h"
#include "netflow.h"

typedef struct flow_entry {
  struct flow_entry *previous;
  struct flow_entry *next;
  struct flowrecord *record;
} flow_entry;

typedef struct flowrecord {
  unsigned int table_id;
  flow_entry flow_cache;
  flow_entry flow_table;
  nf_v5_record_t nf_record;
  ipv4_tuple tuple;
} flowrecord;

typedef struct {
  struct flow_entry *head;
  struct flow_entry *tail;
  unsigned int id;
} flowtable;

flowrecord *flow_retrieve(flowtable *cache, flowtable *table, ipv4_tuple *tuple, unsigned int table_len);
void flow_insert(flowtable *cache, flowtable *table, flowrecord *flowrecord);
void flow_refresh(flowtable *cache, flowrecord *flowrecord);
void flow_expire(nf_peer_t *nf_peer, flowtable *cache, flowtable *table, unsigned long expiration);

#endif

