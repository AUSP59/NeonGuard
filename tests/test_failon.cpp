// SPDX-License-Identifier: Apache-2.0

#include "neonsec/detectors.hpp"
#include "neonsec/window.hpp"
#include <cassert>
#include <vector>
using namespace neonsec;
int main(){
  SlidingWindow w(60);
  Thresholds t; t.portscan_attempts = 1;
  std::vector<Finding> out;
  LogRecord r{1000,"1","2",1,2,"connect","ok",0,"-"};
  w.add(r); detect_portscan(w,r,t,out);
  bool got=false; for(auto& f:out) if(f.type=="portscan") got=true; assert(got);
  return 0;
}
