// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <string>
#include <cstdint>
#include <optional>
namespace neonsec {
struct LogRecord { std::int64_t ts; std::string src_ip; std::string dst_ip; int dst_port{}; std::string protocol; std::string action; std::string status; std::int64_t bytes{}; std::string username; };
std::optional<LogRecord> parse_csv_line(const std::string& header, const std::string& line, std::string& err);
std::optional<LogRecord> parse_ndjson_line(const std::string& line, std::string& err);
std::int64_t parse_timestamp(const std::string& ts_str, std::string& err);
} // namespace neonsec
