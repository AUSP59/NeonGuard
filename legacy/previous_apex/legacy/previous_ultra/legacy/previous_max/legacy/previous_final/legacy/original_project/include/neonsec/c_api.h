/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stddef.h>
#include "neonsec/visibility.hpp"

typedef struct neonsec_engine neonsec_engine;
typedef struct {
  int64_t ts;
  const char* src_ip;
  const char* dst_ip;
  int32_t dst_port;
  const char* protocol;
  const char* action;
  const char* status;
  int64_t bytes;
  const char* username;
} neonsec_log_record;

typedef struct {
  char type[64];
  char key[64];
  char details[128];
  int64_t ts;
} neonsec_finding;

/* Create an engine with simple thresholds; window_sec applies to internal windows. */
NEONSEC_CAPI neonsec_engine* neonsec_engine_new(
  int window_sec,
  int portscan_unique_ports,
  int bruteforce_failures,
  int ddos_events,
  int ddos_unique_sources,
  double anomaly_z);
/* Feed one record, return number of findings written to out (<= max_out). */
NEONSEC_CAPI int neonsec_engine_feed(neonsec_engine* e, const neonsec_log_record* rec, neonsec_finding* out, int max_out);
/* Destroy engine */
NEONSEC_CAPI void neonsec_engine_free(neonsec_engine* e);

#ifdef __cplusplus
}
#endif
