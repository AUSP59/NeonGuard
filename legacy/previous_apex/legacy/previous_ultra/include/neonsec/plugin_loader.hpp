// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <vector>
#include <string>
#include "neonsec/detectors.hpp"
#include "neonsec/window.hpp"

namespace neonsec {

using PluginHook = void(*)(const LogRecord&, const SlidingWindow&, std::vector<Finding>&);

struct LoadedPlugin {
    std::string path;
    void* handle = nullptr;
    PluginHook hook = nullptr;
};

bool load_plugin(const std::string& path, LoadedPlugin& out);
void unload_plugin(LoadedPlugin& p);

} // namespace neonsec
