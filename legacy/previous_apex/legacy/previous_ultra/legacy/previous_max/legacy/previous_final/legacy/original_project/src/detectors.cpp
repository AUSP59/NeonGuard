// SPDX-License-Identifier: Apache-2.0
#include "neonsec/detectors.hpp"
#include <unordered_set>
#include <cmath>
namespace neonsec {
Detectors::Detectors(WindowConfig w, DetectorConfig d): wcfg_(w), dcfg_(d), by_src_(w), by_dst_(w) {}
std::vector<Finding> Detectors::feed(const LogRecord& r){
  std::vector<Finding> out;
  by_src_.add(r, r.src_ip); by_dst_.add(r, r.dst_ip);
  by_src_.evict(r.ts); by_dst_.evict(r.ts);
  { const auto& dq=by_src_.get(r.src_ip); std::unordered_set<int> ports; for(auto& x: dq) if(x.action=="connect") ports.insert(x.dst_port);
    if((int)ports.size()>= dcfg_.portscan_unique_ports) out.push_back({"port_scan", r.src_ip, "unique ports >= threshold", r.ts}); }
  { const auto& dq=by_src_.get(r.src_ip); int fails=0; for(auto it=dq.rbegin(); it!=dq.rend(); ++it){ if(it->action=="auth"){ if(it->status=="fail") ++fails; else break; } } if(fails>=dcfg_.bruteforce_failures) out.push_back({"brute_force", r.src_ip, "consecutive auth fail >= threshold", r.ts}); }
  { const auto& dq=by_dst_.get(r.dst_ip); if((int)dq.size()>=dcfg_.ddos_events){ std::unordered_set<std::string> uniq; for(auto& x: dq) uniq.insert(x.src_ip); if((int)uniq.size()>=dcfg_.ddos_unique_sources) out.push_back({"ddos_volumetric", r.dst_ip, "burst events and unique sources high", r.ts}); } }
  { auto& st = bytes_stats_[r.src_ip]; double mean=st.first, var=st.second; static std::unordered_map<std::string,size_t> count; auto& n=count[r.src_ip]; n+=1; double x=double(r.bytes); double d=x-mean; mean+=d/double(n); double d2=x-mean; var+=d*d2; st={mean,var}; if(n>5 && var>0.0){ double sd=std::sqrt(var/double(n-1)); if(sd>0.0){ double z=(x-mean)/sd; if(std::fabs(z)>=dcfg_.anomaly_z) out.push_back({"bytes_anomaly", r.src_ip, "z-score |z| >= threshold", r.ts}); }} }
  return out;
}
} // namespace neonsec
