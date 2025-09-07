// SPDX-License-Identifier: Apache-2.0

#include "neonsec/plugin_loader.hpp"
#ifdef _WIN32
  #include <windows.h>
#else
  #include <dlfcn.h>
#endif

namespace neonsec {

typedef bool (*RegisterFn)(PluginHook*);

bool load_plugin(const std::string& path, LoadedPlugin& out){
#ifdef _WIN32
    HMODULE h = LoadLibraryA(path.c_str());
    if (!h) return false;
    auto reg = (RegisterFn)GetProcAddress(h, "neonsec_register");
    if (!reg){ FreeLibrary(h); return false; }
    PluginHook hook=nullptr;
    if (!reg(&hook) || !hook){ FreeLibrary(h); return false; }
    out.path = path; out.handle = h; out.hook = hook;
    return true;
#else
    void* h = dlopen(path.c_str(), RTLD_NOW);
    if (!h) return false;
    auto reg = (RegisterFn)dlsym(h, "neonsec_register");
    if (!reg){ dlclose(h); return false; }
    PluginHook hook=nullptr;
    if (!reg(&hook) || !hook){ dlclose(h); return false; }
    out.path = path; out.handle = h; out.hook = hook;
    return true;
#endif
}

void unload_plugin(LoadedPlugin& p){
#ifdef _WIN32
    if (p.handle) FreeLibrary((HMODULE)p.handle);
#else
    if (p.handle) dlclose(p.handle);
#endif
    p.handle = nullptr; p.hook = nullptr;
}

} // namespace neonsec
