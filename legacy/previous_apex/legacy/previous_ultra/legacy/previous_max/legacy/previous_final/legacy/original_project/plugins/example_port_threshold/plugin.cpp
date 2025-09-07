// SPDX-License-Identifier: Apache-2.0
#include "neonsec/log_record.hpp"
#include "neonsec/detectors.hpp"
#include <vector>
using namespace neonsec; extern "C" bool neonsec_register(PluginCallback* out_cb){ if(!out_cb) return false; *out_cb = [](const LogRecord& r){ std::vector<Finding> f; if(r.action=="connect" && r.dst_port>=65000){ f.push_back({"suspicious_high_port", r.src_ip, "dst_port >= 65000", r.ts}); } return f; }; return true; }
