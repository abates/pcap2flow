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

#ifndef __NF_TIME_H__
#define __NF_TIME_H__

#include <sys/time.h>

void time_reset();
void time_update(const struct timeval *new_time);
unsigned long time_sysuptime();
unsigned long time_epoch_sec();
unsigned long time_epoch_msec();

#endif
