

#include <stdio.h>
#include "nf_time.h"

static unsigned long epoch_sec;
static unsigned long epoch_msec;
static unsigned long sys_boot_sec;
static unsigned long sys_boot_msec;

/**
 * Reset the time to zero
 */
void time_reset() {
  epoch_sec = 0;
  epoch_msec = 0;
  sys_boot_sec = 0;
  sys_boot_msec = 0;
}

/**
 * Update the internal time structures.  This makes
 * no change to the actual syste time, only to the
 * way we generate netflow records with respect to
 * time measured in the pcap
 */
void time_update(const struct timeval *new_time) {
  if (epoch_sec == 0) {
    sys_boot_sec = new_time->tv_sec;
    sys_boot_msec = new_time->tv_usec / 1000;
  }
  epoch_sec = new_time->tv_sec;
  epoch_msec = new_time->tv_usec / 1000;
}

/**
 * Get the milliseconds relative to the last boot
 */
unsigned long time_sysuptime() {
  return (1000 * (epoch_sec - sys_boot_sec)) + epoch_msec - sys_boot_msec;
}

/**
 * Get the current time in seconds since 1/1/1970
 */
unsigned long time_epoch_sec() {
  return epoch_sec;
}

unsigned long time_epoch_msec() {
  return epoch_msec;
}

