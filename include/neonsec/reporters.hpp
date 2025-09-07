// SPDX-License-Identifier: Apache-2.0

#pragma once
#include "neonsec/detectors.hpp"
#include <iostream>
#include <fstream>
#include <optional>

namespace neonsec {

struct OutputConfig {
    std::string format = "text"; // or "json"
    std::optional<std::string> file; // path to write findings (append)
};

inline void write_finding(const Finding& f, const OutputConfig& cfg){
    auto line_text = f.type + " key=" + f.key + " ts=" + std::to_string(f.ts) + " " + f.details + "\n";
    auto line_json = std::string("{"type":"") + f.type + "","key":"" + f.key +
                     "","ts":" + std::to_string(f.ts) + ","details":"" + f.details + ""}\n";
    const std::string& line = (cfg.format=="json") ? line_json : line_text;

    // stdout
    std::cout << line;
    // optional file
    if (cfg.file){
        std::ofstream ofs(*cfg.file, std::ios::app);
        if (ofs) ofs << line;
    }
}

} // namespace neonsec
