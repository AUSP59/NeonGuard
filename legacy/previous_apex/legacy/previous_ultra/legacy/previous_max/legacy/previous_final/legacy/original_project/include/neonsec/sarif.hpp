// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "neonsec/detectors.hpp"
#include <string>
#include <vector>
namespace neonsec { bool write_sarif(const std::string& path, const std::vector<Finding>& fs); }
