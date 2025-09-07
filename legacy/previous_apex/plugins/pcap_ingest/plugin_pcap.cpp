// SPDX-License-Identifier: Apache-2.0

#include "neonsec/plugin_loader.hpp"
#include <string>
extern "C" bool neonsec_register(neonsec::PluginHook* out){
  *out = [](const neonsec::LogRecord&, const neonsec::SlidingWindow&, std::vector<neonsec::Finding>& out){
    (void)out; // PCAP ingest would enqueue records; this plugin demonstrates optional linking.
  };
  return true;
}
