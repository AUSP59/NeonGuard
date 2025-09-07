// SPDX-License-Identifier: Apache-2.0
#include "neonsec/csv_reader.hpp"
#include <string>
using namespace neonsec;
extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  std::string s((const char*)data, size);
  auto v = split_csv(s); (void)v; return 0;
}
