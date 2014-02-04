#/bin/sh
# Copyright 2014 Andrew Bates
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

gcc -g -c nf_time.c netflow.c hash.c flowtable.c pcap2flow.c
gcc -g nf_time.o netflow.o hash.o flowtable.o pcap2flow.o -o pcap2flow -lpcap

