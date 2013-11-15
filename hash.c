/**
 * http://burtleburtle.net/bob/hash/evahash.html
 */


#include "hash.h"

/* The whole new hash function */
hash_word_t hash(ipv4_tuple *tuple, hash_word_t initval) {
  int length = sizeof(ipv4_tuple);
  register hash_byte_t *k = (void *)tuple;
  register hash_word_t a,b,c;  /* the internal state */
  hash_word_t          len;    /* how many key bytes still need mixing */

  /* Set up the internal state */
  len = length;
  a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
  c = initval;         /* variable initialization of internal state */

  /*---------------------------------------- handle most of the key */
  while (len >= 12) {
    a=a+(k[0]+((hash_word_t)k[1]<<8)+((hash_word_t)k[2]<<16) +((hash_word_t)k[3]<<24));
    b=b+(k[4]+((hash_word_t)k[5]<<8)+((hash_word_t)k[6]<<16) +((hash_word_t)k[7]<<24));
    c=c+(k[8]+((hash_word_t)k[9]<<8)+((hash_word_t)k[10]<<16)+((hash_word_t)k[11]<<24));
    mix(a,b,c);
    k = k+12; len = len-12;
  }

  /*------------------------------------- handle the last 11 bytes */
  c = c+length;
  /* all the case statements fall through */
  switch(len) {
    case 11: c=c+((hash_word_t)k[10]<<24);
    case 10: c=c+((hash_word_t)k[9]<<16);
    case 9 : c=c+((hash_word_t)k[8]<<8);
    /* the first byte of c is reserved for the length */
    case 8 : b=b+((hash_word_t)k[7]<<24);
    case 7 : b=b+((hash_word_t)k[6]<<16);
    case 6 : b=b+((hash_word_t)k[5]<<8);
    case 5 : b=b+k[4];
    case 4 : a=a+((hash_word_t)k[3]<<24);
    case 3 : a=a+((hash_word_t)k[2]<<16);
    case 2 : a=a+((hash_word_t)k[1]<<8);
    case 1 : a=a+k[0];
    /* case 0: nothing left to add */
  }
  mix(a,b,c);
   /*-------------------------------------------- report the result */
  return c;
}

