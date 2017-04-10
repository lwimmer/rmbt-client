/*******************************************************************************
 * Copyright 2017 Leonhard Wimmer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

#ifndef SRC_RMBT_STATS_H_
#define SRC_RMBT_STATS_H_

#include "rmbt_common.h"

#include <json.h>

json_object *read_tcp_info(int sfd);
void add_tcp_info(int sfd, json_object *array);
void print_tcp_info(int sfd, FILE *file);
json_object *get_utsname(void);

#endif /* SRC_RMBT_STATS_H_ */
