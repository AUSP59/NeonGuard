// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <vector>
#include <string>
namespace neonsec { std::vector<std::string> split_csv(const std::string& line); }

namespace neonsec { void set_csv_dialect(char delim, char quote); }
