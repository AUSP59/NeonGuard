// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <optional>
#include <string>
#include <fstream>
#include <sstream>
#include <cctype>
#include "neonsec/detectors.hpp"

namespace neonsec {

inline std::optional<long long> parse_int64(const std::string& s, size_t start){
    bool neg=false; size_t i=start;
    if (i<s.size() && (s[i]=='-'||s[i]=='+')){ neg=(s[i]=='-'); i++; }
    long long val=0; bool any=false;
    while (i<s.size() && std::isdigit(static_cast<unsigned char>(s[i]))){
        any=true; val = val*10 + (s[i]-'0'); i++;
    }
    if (!any) return std::nullopt;
    return neg? -val : val;
}

inline std::optional<Thresholds> load_thresholds_json(const std::string& path, std::string& err){
    std::ifstream ifs(path);
    if (!ifs){ err = "cannot open file"; return std::nullopt; }
    std::string s((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    Thresholds t{};
    auto find_int = [&](const char* key)->std::optional<int>{
        auto pos = s.find(key);
        if (pos==std::string::npos) return std::nullopt;
        pos = s.find(':', pos); if (pos==std::string::npos) return std::nullopt;
        pos++; while (pos<s.size() && std::isspace(static_cast<unsigned char>(s[pos]))) pos++;
        auto v = parse_int64(s, pos);
        if (!v) return std::nullopt;
        return static_cast<int>(*v);
    };
    if (auto v=find_int(""portscan_attempts"")) t.portscan_attempts=*v;
    if (auto v=find_int(""ddos_events"")) t.ddos_events=*v;
    if (auto v=find_int(""ddos_unique"")) t.ddos_unique=*v;
    if (auto v=find_int(""bruteforce_failures"")) t.bruteforce_failures=*v;
    return t;
}

inline bool validate_thresholds_json(const std::string& path, std::string& err){
    auto t = load_thresholds_json(path, err);
    if (!t) return false;
    if (t->portscan_attempts<=0 || t->ddos_events<=0 || t->ddos_unique<=0 || t->bruteforce_failures<=0){
        err="thresholds must be positive"; return false;
    }
    return true;
}

} // namespace neonsec
