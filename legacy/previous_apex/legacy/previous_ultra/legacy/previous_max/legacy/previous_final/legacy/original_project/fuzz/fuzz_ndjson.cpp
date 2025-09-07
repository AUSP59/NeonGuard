// SPDX-License-Identifier: Apache-2.0
#include "neonsec/log_record.hpp"
#include <string>
#include <optional>
using namespace neonsec;
extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  std::string s((const char*)data, size);
  std::string err; auto r = parse_ndjson_line(s, err);
  (void)r; return 0;
}
