// SPDX-License-Identifier: Apache-2.0
#include "neonsec/plugin.hpp"
#if defined(_WIN32)
#include <windows.h>
#endif
namespace neonsec {
PluginHost::~PluginHost(){
#if defined(_WIN32)
  for(auto& p: plugins_) if(p.handle) FreeLibrary(p.handle);
#else
  for(auto& p: plugins_) if(p.handle) dlclose(p.handle);
#endif
}
bool PluginHost::load(const std::string& path, std::string& err){
#if defined(_WIN32)
  HMODULE h=LoadLibraryA(path.c_str()); if(!h){ err="LoadLibrary failed"; return false; }
  auto fn=reinterpret_cast<RegisterFn>(GetProcAddress(h,"neonsec_register")); if(!fn){ err="register symbol not found"; FreeLibrary(h); return false; }
#else
  void* h=dlopen(path.c_str(), RTLD_NOW); if(!h){ err=dlerror(); return false; }
  auto fn=reinterpret_cast<RegisterFn>(dlsym(h,"neonsec_register")); if(!fn){ err="register symbol not found"; dlclose(h); return false; }
#endif
  PluginCallback cb; if(!fn(&cb)){ err="plugin refused to register";
#if defined(_WIN32)
  FreeLibrary(h);
#else
  dlclose(h);
#endif
  return false; }
  plugins_.push_back(Plugin{path,h,cb}); return true;
}
std::vector<Finding> PluginHost::run_all(const LogRecord& r){ std::vector<Finding> out; for(auto& p: plugins_){ try{ auto v=p.cb(r); out.insert(out.end(), v.begin(), v.end()); } catch(...){} } return out; }
} // namespace neonsec
