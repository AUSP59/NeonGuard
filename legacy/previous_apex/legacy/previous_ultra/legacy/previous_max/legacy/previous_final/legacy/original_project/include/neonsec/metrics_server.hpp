// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <mutex>
namespace neonsec {
class MetricsServer {
public:
  MetricsServer() = default; ~MetricsServer();
  bool start(const std::string& hostport, std::string& err);
  void stop(); void inc_processed(); void inc_finding(const std::string& type);
private:
  std::thread th_; std::atomic<bool> running_{false}; int sock_{-1}; std::atomic<long long> processed_{0};
  std::unordered_map<std::string,long long> finding_; std::mutex mu_;
  void run(const std::string& host, int port);
}; } // namespace neonsec
