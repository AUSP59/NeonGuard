// SPDX-License-Identifier: Apache-2.0
#include "neonsec/c_api.h"
#include "neonsec/detectors.hpp"
#include "neonsec/rules.hpp"
#include "neonsec/plugin.hpp"
#include <vector>
#include <string>
#include <cstring>

using namespace neonsec;

struct neonsec_engine {
  WindowConfig wcfg;
  DetectorConfig dcfg;
  Detectors det;
  RulesEngine rules;
  PluginHost host;
  neonsec_engine(int w, int p, int b, int de, int du, double z)
    : wcfg{(std::int64_t)w, 5000},
      dcfg{p,b,de,du,z},
      det(wcfg, dcfg),
      rules(wcfg) {}
};

extern "C" neonsec_engine* neonsec_engine_new(
  int window_sec, int portscan_unique_ports, int bruteforce_failures,
  int ddos_events, int ddos_unique_sources, double anomaly_z){
  try { return new neonsec_engine(window_sec, portscan_unique_ports, bruteforce_failures, ddos_events, ddos_unique_sources, anomaly_z); }
  catch(...) { return nullptr; }
}

static void copy_str(char* dst, size_t cap, const std::string& s){
  if(cap==0) return;
  size_t n = s.size()<cap-1? s.size(): cap-1;
  std::memcpy(dst, s.data(), n);
  dst[n] = '\0';
}

extern "C" int neonsec_engine_feed(neonsec_engine* e, const neonsec_log_record* rec, neonsec_finding* out, int max_out){
  if(!e || !rec || !out || max_out<=0) return 0;
  LogRecord r{};
  r.ts = rec->ts; r.src_ip = rec->src_ip?rec->src_ip:""; r.dst_ip = rec->dst_ip?rec->dst_ip:"";
  r.dst_port = rec->dst_port; r.protocol = rec->protocol?rec->protocol:"";
  r.action = rec->action?rec->action:""; r.status = rec->status?rec->status:"";
  r.bytes = rec->bytes; r.username = rec->username?rec->username:"";
  auto v1 = e->det.feed(r);
  auto v2 = e->rules.feed(r);
  auto v3 = e->host.run_all(r);
  v1.insert(v1.end(), v2.begin(), v2.end());
  v1.insert(v1.end(), v3.begin(), v3.end());
  int n = (int)v1.size(); if(n>max_out) n = max_out;
  for(int i=0;i<n;++i){
    copy_str(out[i].type, sizeof(out[i].type), v1[i].type);
    copy_str(out[i].key, sizeof(out[i].key), v1[i].key);
    copy_str(out[i].details, sizeof(out[i].details), v1[i].details);
    out[i].ts = v1[i].ts;
  }
  return n;
}

extern "C" void neonsec_engine_free(neonsec_engine* e){ delete e; }
