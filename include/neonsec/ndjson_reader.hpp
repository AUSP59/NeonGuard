// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <string>
#include <optional>
#include <cctype>
#include "neonsec/csv_reader.hpp"

namespace neonsec {

inline std::optional<long long> parse_int(const std::string& s, size_t start){
    bool neg=false; size_t i=start;
    if (i<s.size() && (s[i]=='-'||s[i]=='+')){ neg=(s[i]=='-'); i++; }
    long long val=0; bool any=false;
    while (i<s.size() && std::isdigit(static_cast<unsigned char>(s[i]))){
        any=true; val = val*10 + (s[i]-'0'); i++;
    }
    if (!any) return std::nullopt;
    return neg? -val : val;
}

inline std::optional<std::string> get_json_string(const std::string& s, const char* key){
    auto pos = s.find(key);
    if (pos==std::string::npos) return std::nullopt;
    pos = s.find(':', pos); if (pos==std::string::npos) return std::nullopt;
    pos = s.find('"', pos); if (pos==std::string::npos) return std::nullopt;
    auto end = s.find('"', pos+1); if (end==std::string::npos) return std::nullopt;
    return s.substr(pos+1, end-(pos+1));
}

inline std::optional<long long> get_json_int(const std::string& s, const char* key){
    auto pos = s.find(key);
    if (pos==std::string::npos) return std::nullopt;
    pos = s.find(':', pos); if (pos==std::string::npos) return std::nullopt;
    pos++; // after ':'
    while (pos<s.size() && std::isspace(static_cast<unsigned char>(s[pos]))) pos++;
    return parse_int(s, pos);
}

inline std::optional<LogRecord> parse_ndjson_line(const std::string& s, std::string& err){
    LogRecord r{};
    auto ts = get_json_int(s, "\"ts\""); if (!ts){ err="ts"; return std::nullopt; } r.ts = *ts;
    auto sip = get_json_string(s, "\"src_ip\""); if (!sip){ err="src_ip"; return std::nullopt; } r.src_ip = *sip;
    auto dip = get_json_string(s, "\"dst_ip\""); if (!dip){ err="dst_ip"; return std::nullopt; } r.dst_ip = *dip;
    auto sp = get_json_int(s, "\"src_port\""); if (!sp){ err="src_port"; return std::nullopt; } r.src_port = (int)*sp;
    auto dp = get_json_int(s, "\"dst_port\""); if (!dp){ err="dst_port"; return std::nullopt; } r.dst_port = (int)*dp;
    auto act = get_json_string(s, "\"action\""); r.action = act.value_or("connect");
    auto st = get_json_string(s, "\"status\""); r.status = st.value_or("ok");
    auto by = get_json_int(s, "\"bytes\""); r.bytes = by.value_or(0);
    auto un = get_json_string(s, "\"username\""); r.username = un.value_or("-");
    return r;
}

} // namespace neonsec
