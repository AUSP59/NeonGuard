// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include "neonsec/csv_reader.hpp"

namespace neonsec {

class SlidingWindow {
public:
    explicit SlidingWindow(long long seconds): span_(seconds) {}
    void add(const LogRecord& r){
        q_.push_back(r);
        prune(r.ts);
        // per-dst and per-src totals
        per_dst_total_[r.dst_ip] += 1;
        per_src_total_[r.src_ip] += 1;
        // counts per (src,dst,port)
        counts_dst_[Key3{r.src_ip, r.dst_ip, r.dst_port}] += 1;
        // unique attackers per dst
        uniq_dst_[Key2{r.src_ip, r.dst_ip}] += 1; // presence map via count>0
        // auth failures
        if (r.action=="login" && (r.status=="failed" || r.status=="fail" || r.status=="error"))
            auth_failures_[r.username] += 1;
    }

    void prune(long long now){
        while (!q_.empty() && q_.front().ts < now - span_){
            const auto& r = q_.front();
            // decrement maps
            auto k3 = Key3{r.src_ip, r.dst_ip, r.dst_port};
            auto it3 = counts_dst_.find(k3);
            if (it3!=counts_dst_.end()){
                if (--(it3->second) <= 0) counts_dst_.erase(it3);
            }
            auto k2 = Key2{r.src_ip, r.dst_ip};
            auto it2 = uniq_dst_.find(k2);
            if (it2!=uniq_dst_.end()){
                if (--(it2->second) <= 0) uniq_dst_.erase(it2);
            }
            auto itd = per_dst_total_.find(r.dst_ip);
            if (itd!=per_dst_total_.end()){
                if (--(itd->second) <= 0) per_dst_total_.erase(itd);
            }
            auto its = per_src_total_.find(r.src_ip);
            if (its!=per_src_total_.end()){
                if (--(its->second) <= 0) per_src_total_.erase(its);
            }
            if (r.action=="login" && (r.status=="failed" || r.status=="fail" || r.status=="error")){
                auto itf = auth_failures_.find(r.username);
                if (itf!=auth_failures_.end()){
                    if (--(itf->second) <= 0) auth_failures_.erase(itf);
                }
            }
            q_.pop_front();
        }
    }

    int port_attempts(const std::string& src, const std::string& dst, int dst_port) const {
        auto it = counts_dst_.find(Key3{src,dst,dst_port});
        return (it==counts_dst_.end()) ? 0 : it->second;
    }
    int uniq_attackers(const std::string& dst) const {
        int c=0;
        for (auto const& kv: uniq_dst_){
            if (kv.first.b == dst) c++;
        }
        return c;
    }
    int auth_failures(const std::string& user) const {
        auto it = auth_failures_.find(user);
        return (it==auth_failures_.end()) ? 0 : it->second;
    }

private:
    struct Key3 { std::string a,b; int c; bool operator==(Key3 const& o) const{return a==o.a && b==o.b && c==o.c;}};
    struct Key2 { std::string a,b; bool operator==(Key2 const& o) const{return a==o.a && b==o.b;}};
    struct KH3 { size_t operator()(Key3 const& k) const { return std::hash<std::string>{}(k.a) ^ (std::hash<std::string>{}(k.b)<<1) ^ (std::hash<int>{}(k.c)<<2); }};
    struct KH2 { size_t operator()(Key2 const& k) const { return std::hash<std::string>{}(k.a) ^ (std::hash<std::string>{}(k.b)<<1); }};

    long long span_;
    std::deque<LogRecord> q_;
    std::unordered_map<Key3,int,KH3> counts_dst_;
    std::unordered_map<Key2,int,KH2> uniq_dst_;
    std::unordered_map<std::string,int> per_dst_total_;
    std::unordered_map<std::string,int> per_src_total_;
    std::unordered_map<std::string,int> auth_failures_;
};

} // namespace neonsec
