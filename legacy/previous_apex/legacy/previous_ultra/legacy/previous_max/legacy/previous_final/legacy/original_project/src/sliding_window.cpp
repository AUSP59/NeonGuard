// SPDX-License-Identifier: Apache-2.0
#include "neonsec/sliding_window.hpp"
namespace neonsec {
void SlidingWindow::add(const LogRecord& r, const std::string& key){
  auto& dq = data_[key]; dq.push_back(r);
  if ((int)dq.size() > cfg_.max_records_per_key) dq.pop_front();
}
void SlidingWindow::evict(std::int64_t now){
  for(auto& kv: data_){ auto& dq=kv.second; while(!dq.empty() && (now-dq.front().ts)>cfg_.span_sec) dq.pop_front(); }
}
const std::deque<LogRecord>& SlidingWindow::get(const std::string& key) const {
  static std::deque<LogRecord> empty; auto it=data_.find(key); return it==data_.end()?empty:it->second;
}
std::vector<std::string> SlidingWindow::keys() const{ std::vector<std::string> v; v.reserve(data_.size()); for(auto& kv: data_) v.push_back(kv.first); return v; }
} // namespace neonsec
