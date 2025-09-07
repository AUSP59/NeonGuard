// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "neonsec/detectors.hpp"
#include "neonsec/sliding_window.hpp"
#include <string>
#include <vector>
#include <optional>
namespace neonsec {
struct Config {
  std::string input; std::string input_format{"csv"}; std::string format{"text"}; std::string output;
  WindowConfig wcfg; DetectorConfig dcfg; std::vector<std::string> plugins; std::string metrics; std::string sarif;
  int threads{1}; int sample{1};
};
std::optional<Config> load_config_json(const std::string& path, std::string& err);
void merge_cli_over_config(Config& cfg, const Config& cli);
} // namespace neonsec
