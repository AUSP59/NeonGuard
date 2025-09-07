// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <deque>
#include <unordered_map>
#include "neonsec/csv_reader.hpp"

namespace neonsec {

class SlidingWindow {
public:
    explicit SlidingWindow(long long seconds): span_(seconds) {}
    void add(const LogRecord& r){
        q_.push_back(r);
        prune(r.ts);
        counts_dst_[{r.src_ip, r.dst_ip, r.dst_port}]++;
        uniq_dst_[{r.dst_ip, r.src_ip}]++;
        per_dst_total_[r.dst_ip]++;
        per_src_total_[r.src_ip]++;
    }

    void prune(long long now){
        while(!q_.empty() && (now - q_.front().ts) > span_){
            auto r = q_.front(); q_.pop_front();
            auto k = Key3{r.src_ip, r.dst_ip, r.dst_port};
            auto it = counts_dst_.find(k); if (it!=counts_dst_.end() && it->second>0) it->second--;
            auto k2 = Key2{r.dst_ip, r.src_ip};
            auto it2 = uniq_dst_.find(k2); if (it2!=uniq_dst_.end() && it2->second>0) it2->second--;
            if (per_dst_total_[r.dst_ip]>0) per_dst_total_[r.dst_ip]--;
            if (per_src_total_[r.src_ip]>0) per_src_total_[r.src_ip]--;
        }
    }

    long long span() const { return span_; }

    int port_attempts(const std::string& src, const std::string& dst) const{
        int total=0; for (const auto& [k,v]: counts_dst_) if (k.a==src && k.b==dst) total+=v; return total;
    }
    int uniq_attackers(const std::string& dst) const{
        int u=0; for (const auto& [k,v]: uniq_dst_) if (k.a==dst && v>0) u++; return u;
    }

private:
    struct Key3 { std::string a,b; int c; bool operator==(Key3 const& o) const{return a==o.a && b==o.b && c==o.c;}};
    struct Key2 { std::string a,b; bool operator==(Key2 const& o) const{return a==o.a && b==o.b;}};
    struct KH3 { size_t operator()(Key3 const& k) const { return std::hash<std::string>{}(k.a) ^ (std::hash<std::string>{}(k.b)<<1) ^ std::hash<int>{}(k.c); }};
    struct KH2 { size_t operator()(Key2 const& k) const { return std::hash<std::string>{}(k.a) ^ (std::hash<std::string>{}(k.b)<<1); }};

    long long span_;
    std::deque<LogRecord> q_;
    std::unordered_map<Key3,int,KH3> counts_dst_;
    std::unordered_map<Key2,int,KH2> uniq_dst_;
    std::unordered_map<std::string,int> per_dst_total_;
    std::unordered_map<std::string,int> per_src_total_;
};

} // namespace neonsec
