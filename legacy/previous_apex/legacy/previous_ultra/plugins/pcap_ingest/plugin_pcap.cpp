// SPDX-License-Identifier: Apache-2.0

#include "neonsec/plugin_loader.hpp"
#include <string>
extern "C" bool neonsec_register(neonsec::PluginHook* out){
  *out = [](const neonsec::LogRecord&, const neonsec::SlidingWindow&, std::vector<neonsec::Finding>& out){
    // Placeholder: real PCAP ingestion would enqueue LogRecord from pcap loop
    // This plugin only demonstrates build/link against libpcap when enabled.
    (void)out;
  };
  return true;
}
