/* Copyright 2014 Andrew Bates
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 */

#include <stdio.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <pcap/pcap.h>
#include "nf_time.h"
#include "hash.h"
#include "flowtable.h"
#include <stdlib.h>

#define FLOW_TABLE_SIZE 65536
#define FLOW_TIMER 3600000

static flowtable flowcache;
static flowtable ftable[FLOW_TABLE_SIZE];
static nf_peer_t nf_peer;

void handle_packet(unsigned char *args, const struct pcap_pkthdr *pkthdr, const unsigned char *p) {
  /* lets start with the ether header... */
  struct ether_header *eptr = (struct ether_header *)p;
  const unsigned char *packet = p;
  ipv4_tuple tuple;
  short protocol = 0;
  flowrecord *flowrecord;

  time_update(&pkthdr->ts);

  /* something like llc that we don't care about
    * although this probably breaks matching on IP packets in
    * 802.1q frames
    */
  if (ntohs(eptr->ether_type) > 0x05DC) {
    switch(ntohs(eptr->ether_type)) {
    /* IP Packets are the only ones we care about */
    case ETHERTYPE_IP:
      protocol = p[23];
      /* Ethernet header is 14 bytes wide, not including the preample, which
       * is not retained in pcap files.  Further, the portion of the IP
       * header before the source/destination IPs is 12 bytes.  Therefore
       * we shift the pointer 14 + 12 bytes
       */
      p += 26;

      /** TODO Fix this... it's not smart to simply copy the struct size
       * minus the one value we don't want copied... what if the struct changes
       * and we forget to update this line?!  Bad bad bad practice!
       */
      memcpy(&tuple, p, sizeof(ipv4_tuple) - sizeof(unsigned short));
      tuple.protocol = protocol;

      switch(protocol) {
      case 1:
        tuple.prot.icmp.unused = 0;
        break;
      case 6:
      case 17:
      case 132:
        break;
      default:
        tuple.prot.combined = 0x0000;
      }

      /* retrieve a flow table entry for the packet */
      flowrecord = flow_retrieve(&flowcache, ftable, &tuple, FLOW_TABLE_SIZE);
      if (flowrecord == NULL) {
        printf("Retrieval returned a null record??\n");
      } else {
        if (flowrecord->nf_record.first == 0) {
          flowrecord->nf_record.first = time_sysuptime();
          flowrecord->nf_record.last = time_sysuptime();
        } else {
          flowrecord->nf_record.last = time_sysuptime();
          flow_refresh(&flowcache, flowrecord);
        }

        if (protocol == 6) {
          /**
           * TCP flags field is 21 bytes offset from the source IP in the 
           * IP header.  We previously incremented the packet pointer to
           * be at the source IP field in the packet
           */
          flowrecord->nf_record.tcp_flags |= p[21];
        }

        /* Subtract the ethernet frame from the packet length */
        flowrecord->nf_record.num_bytes += (pkthdr->len - 20);
        flowrecord->nf_record.num_packets++;
      }
      break;
    case ETHERTYPE_ARP:
    case ETHERTYPE_REVARP:
    case ETHERTYPE_LOOPBACK:
      break;
    default:
      fprintf(stderr,"Unknown ethertype 0x%04x\n", ntohs(eptr->ether_type));
      break;
    }
  }

  if (time_sysuptime() > FLOW_TIMER) {
    flow_expire(&nf_peer, &flowcache, ftable, time_sysuptime() - FLOW_TIMER);
  }
}

int main(int argc, char **argv) {
  pcap_t *fh;
  char errbuf[PCAP_ERRBUF_SIZE];
  u_char* args = NULL;
  struct timeval time;
  struct in_addr peer_ip;

  if (argc < 4) {
    printf("Usage: %s <input pcap file> <netflow ip> <netflow port>\n", argv[0]);
    return -1;
  }

  inet_aton(argv[2], &peer_ip);
  nf_init_peer(&nf_peer, &peer_ip, atoi(argv[3]));

  fh = pcap_open_offline(argv[1], errbuf);
  if (fh == NULL) {
    printf("Failed to open %s: %s\n", argv[1], errbuf);
    return -1;
  }

  memset(ftable, 0, sizeof(ftable));

  time_reset();

  pcap_loop(fh, -1, handle_packet, args);

  /* Dump reamining flow record */
  flow_expire(&nf_peer, &flowcache, ftable, time_sysuptime() + FLOW_TIMER);
  return 0;
}
