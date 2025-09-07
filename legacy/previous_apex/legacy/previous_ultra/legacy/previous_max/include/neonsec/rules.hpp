// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <optional>
#include <string>
#include <fstream>
#include <sstream>
#include <cctype>
#include "neonsec/detectors.hpp"

namespace neonsec {

inline std::optional<Thresholds> load_thresholds_json(const std::string& path, std::string& err){
    std::ifstream ifs(path);
    if (!ifs){ err = "cannot open file"; return std::nullopt; }
    std::string s((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    Thresholds t{};
    auto find_int = [&](const char* key)->std::optional<int>{
        auto pos = s.find(key);
        if (pos==std::string::npos) return std::nullopt;
        pos = s.find(':', pos); if (pos==std::string::npos) return std::nullopt;
        ++pos;
        while (pos<s.size() && std::isspace(static_cast<unsigned char>(s[pos]))) ++pos;
        std::string num;
        while (pos<s.size() && (std::isdigit(static_cast<unsigned char>(s[pos])))) num.push_back(s[pos++]);
        if (num.empty()) return std::nullopt;
        return std::stoi(num);
    };
    if (auto v=find_int("\"portscan_attempts\"")) t.portscan_attempts=*v;
    if (auto v=find_int("\"ddos_events\"")) t.ddos_events=*v;
    if (auto v=find_int("\"ddos_unique\"")) t.ddos_unique=*v;
    return t;
}

inline bool validate_thresholds_json(const std::string& path, std::string& err){
    auto t = load_thresholds_json(path, err);
    if (!t) return false;
    if (t->portscan_attempts<=0 || t->ddos_events<=0 || t->ddos_unique<=0){
        err="thresholds must be positive"; return false;
    }
    return true;
}

} // namespace neonsec
