// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "neonsec/detectors.hpp"
#include <ostream>
#include <string>
namespace neonsec {
void print_text(std::ostream& out, const Finding& f, bool color=false);
void print_json(std::ostream& out, const Finding& f);
void print_ndjson(std::ostream& out, const Finding& f);
std::string json_escape(const std::string& s);
} // namespace neonsec
