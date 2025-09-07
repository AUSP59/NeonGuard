// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <string>
#include <vector>
#include "neonsec/log_record.hpp"
namespace neonsec {
#ifdef NEONSEC_WITH_PCAP
bool read_pcap_file(const std::string& path, std::vector<LogRecord>& out, std::string& err);
bool read_pcap_live(const std::string& iface, std::vector<LogRecord>& out, std::string& err);
#else
inline bool read_pcap_file(const std::string&, std::vector<LogRecord>&, std::string& err){ err="PCAP disabled"; return false; }
inline bool read_pcap_live(const std::string&, std::vector<LogRecord>&, std::string& err){ err="PCAP disabled"; return false; }
#endif
} // namespace neonsec
