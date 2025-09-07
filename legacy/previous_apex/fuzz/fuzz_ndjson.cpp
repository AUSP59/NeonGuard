// SPDX-License-Identifier: Apache-2.0

#include "neonsec/ndjson_reader.hpp"
#include <string>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size){
  std::string s((const char*)Data, Size);
  std::string err; (void)err;
  auto r = neonsec::parse_ndjson_line(s, err);
  return 0;
}
