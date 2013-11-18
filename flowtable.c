
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "flowtable.h"
#include "netflow.h"

flowrecord *flow_retrieve(flowtable *cache, flowtable **table, ipv4_tuple *tuple, unsigned int table_len) {
  flow_entry *entry = NULL;
  flowrecord *fr = NULL;

  unsigned int table_index = hash(tuple, 0xebebebeb) % table_len;

  if (table[table_index] == NULL) {
    table[table_index] = malloc(sizeof(flowtable));
    if (table[table_index] == NULL) {
      fprintf(stderr, "Memory allocation failure\n");
      exit(-1);
    }
    table[table_index]->id = table_index;
  } else {
    entry = table[table_index]->head;
  }

  while (entry != NULL) {
    if (memcmp(&entry->record->tuple, tuple, sizeof(ipv4_tuple)) == 0) {
      break;
    }
    entry = entry->next;
  }

  /**
   * if a matching flow record was not found
   * then create a new one
   */
  if (entry == NULL) {
    fr = malloc(sizeof(flowrecord));
    if (fr == NULL) {
      fprintf(stderr, "Memory allocation falure\n");
      exit(-1);
    }

    memset(&fr->nf_record, 0, sizeof(nf_v5_record_t));
    memcpy(&fr->tuple, tuple, sizeof(ipv4_tuple));

    fr->table_id = table_index;
    fr->flow_table.next = NULL;
    fr->flow_table.previous = NULL;
    fr->flow_table.record = fr;

    fr->flow_cache.next = NULL;
    fr->flow_cache.previous = NULL;
    fr->flow_cache.record = fr;

    fr->nf_record.first = 0;
    fr->nf_record.last = 0;
    fr->nf_record.source_ip = tuple->source_ip;
    fr->nf_record.destination_ip = tuple->destination_ip;
    fr->nf_record.source_port = tuple->prot.port.source_port;
    fr->nf_record.destination_port = tuple->prot.port.destination_port;
    fr->nf_record.protocol = htons(tuple->protocol);
    
    flow_insert(cache, table[table_index], fr);
  } else {
    fr = entry->record;
  }
  return fr;
}

void flow_insert(flowtable *cache, flowtable *table, flowrecord *flowrecord) {
  flow_entry *cache_entry = &flowrecord->flow_cache;
  flow_entry *table_entry = &flowrecord->flow_table;

  if (table->head == NULL) {
    table->head = table_entry;
    table->tail = table_entry;
  } else {
    table_entry->previous = table->tail;
    table->tail->next = table_entry;
    table->tail = table_entry;
  }

  if (cache->head == NULL) {
    cache->head = cache_entry;
    cache->tail = cache_entry;
  } else {
    cache->head->previous = cache_entry;
    cache_entry->next = cache->head;
    cache->head = cache_entry;
  }
}

void flow_refresh(flowtable *cache, flowrecord *flowrecord) {
  struct flow_entry *flow_entry = &flowrecord->flow_cache;

  /* do nothing if the previous pointer is null since the
   * entry is already at the top
   */
  if (flow_entry->previous != NULL) {
    /* Remove the entry from the bottom of the list */
    if (flow_entry->next == NULL) {
      flow_entry->previous->next = NULL;
      cache->tail = flow_entry->previous;
    /* Remove the entry from the middle of the list */
    } else {
      flow_entry->previous->next = flow_entry->next;
      flow_entry->next->previous = flow_entry->previous;
    }
    /* Move it to the top of the stack */
    flow_entry->previous = NULL;
    flow_entry->next = cache->head;
    cache->head->previous = flow_entry;
    cache->head = flow_entry;
  }
}

void flow_expire(nf_peer_t *nf_peer, flowtable *cache, flowtable **table, unsigned long expiration) {
  flow_entry *export_cache;
  flow_entry *export_table;
  nf_v5_packet_t nf_packet;
  unsigned int num_records = 0;

  while(cache->tail != NULL && cache->tail->record->nf_record.last < expiration) {
    export_cache = cache->tail;
    export_table = &export_cache->record->flow_table;
    flowrecord *record = export_cache->record;
    memcpy(&nf_packet.records[num_records], &record->nf_record, sizeof(nf_v5_record_t));
    /* Correct byte ordering */
    nf_packet.records[num_records].first = htonl(nf_packet.records[num_records].first);
    nf_packet.records[num_records].last = htonl(nf_packet.records[num_records].last);
    nf_packet.records[num_records].num_packets = htonl(nf_packet.records[num_records].num_packets);
    nf_packet.records[num_records].num_bytes = htonl(nf_packet.records[num_records].num_bytes);

    num_records++;

    if (num_records == 30) {
      nf_export(nf_peer, &nf_packet, num_records);
      num_records = 0;
    }

    /* Remove the entry from the bottom of the stack */
    cache->tail = export_cache->previous;

    /* Remove the entry from the flow table */
    if (export_table->next == NULL && export_table->previous == NULL) {
      free(table[record->table_id]);
      table[record->table_id] = NULL;
    } else if (export_table->previous == NULL) {
      export_table->next->previous = NULL;
      table[record->table_id]->head = export_table->next;
    } else if (export_table->next == NULL) {
      export_table->previous->next = NULL;
      table[record->table_id]->tail = export_table->previous;
    } else {
      export_table->previous->next = export_table->next;
      export_table->next->previous = export_table->previous;
    }

    free(export_cache->record);
  }
  if (num_records > 0) {
    nf_export(nf_peer, &nf_packet, num_records);
  }
}

