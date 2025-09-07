// SPDX-License-Identifier: Apache-2.0

#pragma once
#include "neonsec/detectors.hpp"
#include <iostream>

namespace neonsec {

inline void report_text(const Finding& f){
    std::cout << "[" << f.type << "] " << f.key << " @ " << f.ts << " :: " << f.details << "\n";
}

inline void report_json(const Finding& f){
    std::cout << "{\"type\":\"" << f.type << "\",\"key\":\"" << f.key
              << "\",\"ts\":" << f.ts << ",\"details\":\"" << f.details << "\"}\n";
}

} // namespace neonsec
