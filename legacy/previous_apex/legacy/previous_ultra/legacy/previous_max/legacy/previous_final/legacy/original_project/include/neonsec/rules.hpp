// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "neonsec/log_record.hpp"
#include "neonsec/sliding_window.hpp"
#include <string>
#include <vector>
#include <optional>
namespace neonsec {
enum class CmpOp { EQ, NE, GE, GT, LE, LT, REGEX };
struct Condition { std::string field; CmpOp op; std::string value; };
struct Rule { std::string name; std::vector<Condition> when; std::string group_by; std::int64_t within_sec{60}; int count_ge{0}; long long sum_bytes_ge{0}; std::string emit_type; std::string emit_details; };
struct RulesConfig { std::vector<Rule> rules; };
std::optional<RulesConfig> load_rules_json(const std::string& path, std::string& err);
class RulesEngine {
 public: explicit RulesEngine(WindowConfig wcfg): win_(wcfg) {}
  void add_rule(const Rule& r){ rules_.push_back(r); }
  std::vector<Finding> feed(const LogRecord& r);
 private:
  WindowConfig wcfg_; SlidingWindow win_; std::vector<Rule> rules_;
  bool matches(const Rule& r, const LogRecord& rec) const;
  std::string key_for(const Rule& r, const LogRecord& rec) const;
}; } // namespace neonsec
