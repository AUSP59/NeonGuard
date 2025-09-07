// SPDX-License-Identifier: Apache-2.0
#include "neonsec/log_record.hpp"
#include <sstream>
#include <iomanip>
#include <ctime>
namespace neonsec {
// enhanced ISO8601 parsing with timezone offsets
static bool digits(const std::string& s){ if(s.empty()) return false; for(char c: s) if(c<'0'||c>'9') return false; return true; }
std::int64_t parse_timestamp(const std::string& ts_str, std::string& err) {
  // Accepts epoch seconds, YYYY-MM-DDTHH:MM:SSZ, and with timezone offsets ±HH:MM
  if (digits(ts_str)) { try { return std::stoll(ts_str); } catch(...) { err="invalid epoch"; return -1; } }
  std::tm tm{};
  if (ts_str.size()>=20 && ts_str.back()=='Z') {
    std::istringstream ss(ts_str.substr(0, ts_str.size()-1));
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
#if defined(_WIN32)
    time_t t = _mkgmtime(&tm);
#else
    time_t t = timegm(&tm);
#endif
    if (t>=0) return (std::int64_t)t;
  }

      // Try with timezone offset like +02:00 or -05:30
      if (ts_str.size()>=25 && (ts_str[19]=='+' || ts_str[19]=='-') && ts_str[22]==':') {
        std::tm tm{};
        try{
          std::string core = ts_str.substr(0,19);
          std::istringstream ss(core);
          ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
#if defined(_WIN32)
          time_t t = _mkgmtime(&tm);
#else
          time_t t = timegm(&tm);
#endif
          int sign = ts_str[19]=='+'? +1 : -1;
          int hh = std::stoi(ts_str.substr(20,2));
          int mm = std::stoi(ts_str.substr(23,2));
          int offset = sign * (hh*3600 + mm*60);
          return (std::int64_t)t - offset; // convert local-with-offset to UTC epoch
        } catch(...) { /* fallthrough */ }
      }
  err="unsupported timestamp"; return -1;
}
} // namespace neonsec
