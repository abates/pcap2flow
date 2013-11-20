

#ifndef __NF_TIME_H__
#define __NF_TIME_H__

#include <sys/time.h>

void time_reset();
void time_update(const struct timeval *new_time);
unsigned long time_sysuptime();
unsigned long time_epoch_sec();
unsigned long time_epoch_msec();

#endif
