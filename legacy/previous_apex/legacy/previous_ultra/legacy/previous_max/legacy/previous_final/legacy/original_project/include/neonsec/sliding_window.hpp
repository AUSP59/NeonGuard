// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "neonsec/log_record.hpp"
#include <deque>
#include <unordered_map>
#include <vector>
#include <string>
namespace neonsec {
struct WindowConfig { std::int64_t span_sec{60}; int max_records_per_key{5000}; };
class SlidingWindow {
 public:
  explicit SlidingWindow(WindowConfig cfg): cfg_(cfg) {}
  void add(const LogRecord& r, const std::string& key);
  void evict(std::int64_t now);
  const std::deque<LogRecord>& get(const std::string& key) const;
  std::vector<std::string> keys() const;
 private:
  WindowConfig cfg_;
  std::unordered_map<std::string, std::deque<LogRecord>> data_;
}; } // namespace neonsec
