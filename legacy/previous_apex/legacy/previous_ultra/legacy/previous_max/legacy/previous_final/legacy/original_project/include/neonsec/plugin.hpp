// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "neonsec/detectors.hpp"
#include <functional>
#include <string>
#include <vector>
#if defined(_WIN32)
  #include <windows.h>
#else
  #include <dlfcn.h>
#endif
namespace neonsec {
using PluginCallback = std::function<std::vector<Finding>(const LogRecord&)>;
struct Plugin { std::string path;
#if defined(_WIN32)
HMODULE handle{nullptr};
#else
void* handle{nullptr};
#endif
PluginCallback cb; };
class PluginHost {
 public: ~PluginHost();
  bool load(const std::string& path, std::string& err);
  std::vector<Finding> run_all(const LogRecord& r);
 private: std::vector<Plugin> plugins_;
};
using RegisterFn = bool(*)(PluginCallback* out_cb);
} // namespace neonsec
