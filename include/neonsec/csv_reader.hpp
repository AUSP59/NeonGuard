// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <string>
#include <vector>
#include <optional>
#include <sstream>
#include <cstdint>

namespace neonsec {

struct LogRecord {
    long long ts{};          // epoch seconds
    std::string src_ip;
    std::string dst_ip;
    int src_port{};
    int dst_port{};
    std::string action;
    std::string status;
    long long bytes{};
    std::string username;
};

inline std::optional<LogRecord> parse_csv_line(const std::string& line, std::string& err){
    std::stringstream ss(line);
    std::string tok;
    std::vector<std::string> cols;
    while (std::getline(ss, tok, ',')) cols.push_back(tok);
    if (cols.size() != 9) { err = "expected 9 columns"; return std::nullopt; }
    try{
        LogRecord r{};
        r.ts = std::stoll(cols[0]); r.src_ip = cols[1]; r.dst_ip = cols[2];
        r.src_port = std::stoi(cols[3]); r.dst_port = std::stoi(cols[4]);
        r.action = cols[5]; r.status = cols[6]; r.bytes = std::stoll(cols[7]); r.username = cols[8];
        return r;
    }catch(...){ err = "parse error"; return std::nullopt; }
}

} // namespace neonsec
