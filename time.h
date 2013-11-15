

#ifndef __TIME_H__
#define __TIME_H__

#include <sys/time.h>

void time_reset();
void time_update(const struct timeval *new_time);
unsigned long time_sysuptime();
unsigned long time_epoch();

#endif
