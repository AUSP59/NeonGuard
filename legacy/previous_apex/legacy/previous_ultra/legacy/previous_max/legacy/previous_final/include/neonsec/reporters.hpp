
#pragma once
#include "neonsec/detectors.hpp"
#include <iostream>

namespace neonsec {

inline void report_text(const Finding& f){
    std::cout << "[" << f.type << "] " << f.key << " @ " << f.ts << " :: " << f.details << "\n";
}

} // namespace neonsec
