// SPDX-License-Identifier: Apache-2.0
#include "neonsec/log_record.hpp"
#include <cassert>
#include <string>
using namespace neonsec;
int main(){
  std::string err;
  auto ok = parse_ndjson_line("{"ts":1725499200,"src_ip":"a","dst_ip":"b","dst_port":1,"protocol":"TCP","action":"connect","status":"ok","bytes":10,"username":"u"}", err);
  assert(ok.has_value()); assert(ok->dst_port==1);
  return 0;
}
