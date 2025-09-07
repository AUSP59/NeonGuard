// SPDX-License-Identifier: Apache-2.0
#include "neonsec/reporters.hpp"
#include <cstdio>
namespace neonsec {
static std::string to_iso(std::int64_t ts){ std::time_t t=(std::time_t)ts; std::tm g{}; #if defined(_WIN32)
  g = *gmtime(&t);
#else
  g = *gmtime(&t);
#endif
  std::ostringstream ss; ss<<std::put_time(&g, "%Y-%m-%dT%H:%M:%SZ"); return ss.str(); }
void print_text(std::ostream& out, const Finding& f, bool color, bool iso){ if(color){ const char* Y="\x1b[33m"; const char* C="\x1b[36m"; const char* R="\x1b[0m"; out << Y<<"["<<(iso?to_iso(f.ts):std::to_string(f.ts))<<"]"<<R<<" "<<C<<f.type<<R<<" key="<<f.key<<" details="<<f.details<<"\n"; } else { out << "["<<(iso?to_iso(f.ts):std::to_string(f.ts))<<"] "<<f.type<<" key="<<f.key<<" details="<<f.details<<"\n"; } }
std::string json_escape(const std::string& s){ std::string o; o.reserve(s.size()+8); for(char c: s){ switch(c){ case '"': o+="\\\""; break; case '\\': o+="\\\\"; break; case '\n': o+="\\n"; break; case '\r': o+="\\r"; break; case '\t': o+="\\t"; break; default: if((unsigned char)c<0x20){ char b[7]; std::snprintf(b,sizeof(b),"\\u%04x", c); o+=b; } else o+=c; } } return o; }
void print_json(std::ostream& out, const Finding& f){ out << "{ \"type\": \"" << json_escape(f.type) << "\", \"key\": \"" << json_escape(f.key) << "\", \"details\": \"" << json_escape(f.details) << "\", \"ts\": " << f.ts << " }\n"; }
void print_ndjson(std::ostream& out, const Finding& f){ print_json(out, f); }
} // namespace neonsec

void print_yaml(std::ostream& out, const Finding& f){ out<<"- ts: "<<f.ts<<"\n  type: "<<f.type<<"\n  key: "<<f.key<<"\n  details: "<<f.details<<"\n"; }
