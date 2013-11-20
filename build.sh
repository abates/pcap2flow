#/bin/sh

gcc -g -c nf_time.c netflow.c hash.c flowtable.c pcap2flow.c
gcc -g nf_time.o netflow.o hash.o flowtable.o pcap2flow.o -o pcap2flow -lpcap

