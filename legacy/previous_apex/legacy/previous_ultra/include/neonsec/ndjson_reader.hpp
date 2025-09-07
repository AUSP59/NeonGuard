// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <string>
#include <optional>
#include "neonsec/csv_reader.hpp"

namespace neonsec {

inline std::optional<LogRecord> parse_ndjson_line(const std::string& s, std::string& err){
    auto get_str = [&](const char* key)->std::optional<std::string>{
        auto pos = s.find(key);
        if (pos==std::string::npos) return std::nullopt;
        pos = s.find(':', pos); if (pos==std::string::npos) return std::nullopt;
        pos = s.find('"', pos); if (pos==std::string::npos) return std::nullopt;
        auto end = s.find('"', pos+1); if (end==std::string::npos) return std::nullopt;
        return s.substr(pos+1, end-(pos+1));
    };
    auto get_int = [&](const char* key)->std::optional<long long>{
        auto pos = s.find(key);
        if (pos==std::string::npos) return std::nullopt;
        pos = s.find(':', pos); if (pos==std::string::npos) return std::nullopt;
        ++pos;
        while (pos<s.size() && (s[pos]==' ')) ++pos;
        std::string num;
        while (pos<s.size() && (s[pos]=='-' || (s[pos]>='0' && s[pos]<='9'))) num.push_back(s[pos++]);
        if (num.empty()) return std::nullopt;
        try{ return std::stoll(num);}catch(...){return std::nullopt;}
    };

    LogRecord r{};
    auto ts = get_int("\"ts\""); if (!ts){ err="ts"; return std::nullopt; } r.ts = *ts;
    auto sip = get_str("\"src_ip\""); if (!sip){ err="src_ip"; return std::nullopt; } r.src_ip = *sip;
    auto dip = get_str("\"dst_ip\""); if (!dip){ err="dst_ip"; return std::nullopt; } r.dst_ip = *dip;
    auto sp = get_int("\"src_port\""); if (!sp){ err="src_port"; return std::nullopt; } r.src_port = (int)*sp;
    auto dp = get_int("\"dst_port\""); if (!dp){ err="dst_port"; return std::nullopt; } r.dst_port = (int)*dp;
    auto act = get_str("\"action\""); r.action = act.value_or("connect");
    auto st = get_str("\"status\""); r.status = st.value_or("ok");
    auto by = get_int("\"bytes\""); r.bytes = by.value_or(0);
    auto un = get_str("\"username\""); r.username = un.value_or("-");
    return r;
}

} // namespace neonsec
