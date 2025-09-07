// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "neonsec/log_record.hpp"
#include "neonsec/sliding_window.hpp"
#include <vector>
#include <string>
#include <unordered_map>
namespace neonsec {
struct DetectorConfig { int portscan_unique_ports{20}; int bruteforce_failures{5}; int ddos_events{500}; int ddos_unique_sources{100}; double anomaly_z{3.5}; };
struct Finding { std::string type; std::string key; std::string details; std::int64_t ts; };
class Detectors {
 public: Detectors(WindowConfig wcfg, DetectorConfig dcfg);
  std::vector<Finding> feed(const LogRecord& r);
 private: WindowConfig wcfg_; DetectorConfig dcfg_; SlidingWindow by_src_; SlidingWindow by_dst_; std::unordered_map<std::string, std::pair<double,double>> bytes_stats_;
}; } // namespace neonsec
