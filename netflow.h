

#ifndef __NETFLOW_H__
#define __NETFLOW_H__

#include <netinet/in.h>

typedef struct {
  uint16_t version;           /* bytes 0-1 */
  uint16_t count;             /* bytes 2-3 */
  uint32_t sys_uptime;        /* bytes 4-7 */
  uint32_t ts_sec;            /* bytes 8-11 */
  uint32_t ts_msec;           /* bytes 12-15 */
  uint32_t sequence;          /* bytes 16-19 */
  uint8_t  engine_type;       /* byte 20 */
  uint8_t  engine_id;         /* byte 21 */
  uint16_t sampling_interval; /* byte 22-23 */
} nf_v5_header_t;

typedef struct {
  uint32_t source_ip;        /* bytes 0-3: Flow source IPv4 address */
  uint32_t destination_ip;   /* bytes 4-7: Flow destination IPv4 address */
  uint32_t next_hop;         /* bytes 8-11: Next hop router ID (IPv4 Address) */
  uint16_t iif_index;        /* bytes 12-13: Input SNMP interface index */
  uint16_t oif_index;        /* bytes 14-15: Output SNMP interface index */
  uint32_t num_packets;      /* bytes 16-19: Number of packets in the flow */
  uint32_t num_bytes;        /* bytes 20-23: Number of bytes in the flow */
  uint32_t first;            /* bytes 24-27: System uptime when flow started */
  uint32_t last;             /* bytes 28-31: System uptime when flow ended */
  uint16_t source_port;      /* bytes 32-33: Source port for tcp/udp/sctp flows.  Zero for everything else */
  uint16_t destination_port; /* bytes 34-35: Destination port for tcp/udp/sctp flows.  ICMP type and code for ICMP and zero for everything else */
  uint8_t  mid_pad;          /* byte 36: zero pad */
  uint8_t  tcp_flags;        /* byte 37: tcp flags or zero */
  uint8_t  protocol;         /* byte 38: IP protocol number */
  uint8_t  tos;              /* byte 39: IP Type of Service */
  uint16_t source_as;        /* bytes 40-41: BGP source ASN */
  uint16_t destination_as;   /* bytes 42-43: BGP destination ASN */
  uint8_t  source_prefix;    /* byte 44: number of bits in the source route mask */
  uint8_t  dest_prefix;      /* byte 45: number of bites in the destination route mask */
  uint16_t end_pad;          /* bytes 46-47: zero pad */
} nf_v5_record_t;

typedef struct {
  nf_v5_header_t header;
  nf_v5_record_t records[30];
} nf_v5_packet_t;

typedef struct {
  int socket;
  struct sockaddr_in sockaddr;
} nf_peer_t;

void nf_init_peer(nf_peer_t *nf_peer, struct in_addr *peer_ip, unsigned short peer_port);
void nf_export(nf_peer_t *nf_peer, nf_v5_packet_t *packet, unsigned int num_records);

#endif
