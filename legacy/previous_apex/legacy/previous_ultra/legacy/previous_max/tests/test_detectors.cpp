// SPDX-License-Identifier: Apache-2.0

#include "neonsec/window.hpp"
#include "neonsec/detectors.hpp"
#include <cassert>
#include <vector>
using namespace neonsec;

int main(){
  SlidingWindow w(60);
  Thresholds t; t.portscan_attempts = 3; t.ddos_unique = 2;
  std::vector<Finding> out;

  // Portscan
  long long ts = 1000;
  for (int p=1;p<=3;p++){
    LogRecord r{ts++,"1.1.1.1","2.2.2.2",1234,p,"connect","ok",10,"-"};
    w.add(r); detect_portscan(w, r, t, out);
  }
  bool got_scan=false; for (auto& f: out) if (f.type=="portscan") got_scan=true; assert(got_scan);

  // DDoS
  out.clear();
  LogRecord a{ts,"3.3.3.3","9.9.9.9",1000,80,"connect","ok",1,"-"};
  LogRecord b{ts+1,"4.4.4.4","9.9.9.9",1000,80,"connect","ok",1,"-"};
  w.add(a); detect_ddos(w,a,t,out);
  w.add(b); detect_ddos(w,b,t,out);
  bool got_ddos=false; for (auto& f: out) if (f.type=="ddos") got_ddos=true; assert(got_ddos);
  return 0;
}
