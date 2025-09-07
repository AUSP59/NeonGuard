
#pragma once
#include "neonsec/window.hpp"
#include <vector>
#include <string>

namespace neonsec {

struct Finding {
    std::string type;     // "portscan" | "ddos" | "anomaly"
    std::string key;      // ip or pair
    long long ts;
    std::string details;
};

struct Thresholds {
    int portscan_attempts = 20;
    int ddos_events = 200;
    int ddos_unique = 50;
};

inline void detect_portscan(const SlidingWindow& w, const LogRecord& r, const Thresholds& t, std::vector<Finding>& out){
    int attempts = w.port_attempts(r.src_ip, r.dst_ip);
    if (attempts >= t.portscan_attempts){
        out.push_back({"portscan", r.src_ip + " -> " + r.dst_ip, r.ts, "attempts="+std::to_string(attempts)});
    }
}

inline void detect_ddos(const SlidingWindow& w, const LogRecord& r, const Thresholds& t, std::vector<Finding>& out){
    int uniq = w.uniq_attackers(r.dst_ip);
    if (uniq >= t.ddos_unique){
        out.push_back({"ddos", r.dst_ip, r.ts, "unique_attackers="+std::to_string(uniq)});
    }
}

} // namespace neonsec
