#/bin/sh

gcc -g -c time.c netflow.c hash.c flowtable.c pcap2flow.c
gcc -g time.o netflow.o hash.o flowtable.o pcap2flow.o -o pcap2flow -lpcap

