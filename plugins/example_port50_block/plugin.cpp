// SPDX-License-Identifier: Apache-2.0

#include "neonsec/plugin_loader.hpp"
extern "C" bool neonsec_register(neonsec::PluginHook* out){
  *out = [](const neonsec::LogRecord& r, const neonsec::SlidingWindow& w, std::vector<neonsec::Finding>& out){
    (void)w;
    if (r.dst_port == 50){
      out.push_back({"policy", r.src_ip + " -> " + r.dst_ip, r.ts, "dst_port=50 blocked by policy"});
    }
  };
  return true;
}
