// SPDX-License-Identifier: Apache-2.0

#include "neonsec/ndjson_reader.hpp"
#include <cassert>
#include <string>
using namespace neonsec;
int main(){
  std::string err;
  auto r = parse_ndjson_line("{\"ts\":1725499200,\"src_ip\":\"a\",\"dst_ip\":\"b\",\"src_port\":1,\"dst_port\":2,\"action\":\"c\",\"status\":\"ok\",\"bytes\":9,\"username\":\"u\"}", err);
  assert(r.has_value());
  assert(r->dst_port==2);
  return 0;
}
