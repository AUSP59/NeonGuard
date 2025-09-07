// SPDX-License-Identifier: Apache-2.0

#include "neonsec/csv_reader.hpp"
#include <cassert>
#include <string>
using namespace neonsec;
int main(){
  std::string err;
  auto r = parse_csv_line("1725499200,10.0.0.1,10.0.0.2,1234,80,connect,ok,42,alice", err);
  assert(r.has_value());
  assert(r->ts==1725499200);
  assert(r->dst_port==80);
  assert(r->bytes==42);
  return 0;
}
