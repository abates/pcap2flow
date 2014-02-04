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

#ifndef __HASH_H__
#define __HASH_H__

#include <stdint.h>

typedef unsigned char hash_byte_t;
typedef uint32_t hash_word_t;

/* The mixing step */
#define mix(a,b,c) \
{ \
  a=a-b;  a=a-c;  a=a^(c>>13); \
  b=b-c;  b=b-a;  b=b^(a<<8);  \
  c=c-a;  c=c-b;  c=c^(b>>13); \
  a=a-b;  a=a-c;  a=a^(c>>12); \
  b=b-c;  b=b-a;  b=b^(a<<16); \
  c=c-a;  c=c-b;  c=c^(b>>5);  \
  a=a-b;  a=a-c;  a=a^(c>>3);  \
  b=b-c;  b=b-a;  b=b^(a<<10); \
  c=c-a;  c=c-b;  c=c^(b>>15); \
}

typedef struct {
  uint32_t source_ip;
  uint32_t destination_ip;
  union {
    uint32_t combined;
    struct {
      uint16_t unused;
      uint8_t type;
      uint8_t code;
    } icmp;
    struct {
      uint16_t source_port;
      uint16_t destination_port;
    } port;
  } prot;
  uint8_t protocol;
} ipv4_tuple;

/* The whole new hash function */
hash_word_t hash(ipv4_tuple *tuple, hash_word_t initval);

#endif
