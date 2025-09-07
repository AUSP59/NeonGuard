// SPDX-License-Identifier: Apache-2.0
#include "neonsec/log_record.hpp"
#include <string>
#include <optional>
#include <cctype>
#include <cstdlib>
namespace neonsec {
static void skip_ws(const std::string& s, size_t& i){ while(i<s.size() && std::isspace((unsigned char)s[i])) ++i; }
static bool match(const std::string& s, size_t& i, char c){ skip_ws(s,i); if(i<s.size() && s[i]==c){ ++i; return true; } return false; }
static std::string parse_string(const std::string& s, size_t& i, bool& ok){
  skip_ws(s,i); if(i>=s.size()||s[i]!='"'){ ok=false; return {}; } ++i; std::string out;
  while(i<s.size()){ char c=s[i++]; if(c=='"') break; if(c=='\\' && i<s.size()){ char n=s[i++]; out.push_back(n); } else out.push_back(c); }
  ok=true; return out;
}
static double parse_number(const std::string& s, size_t& i, bool& ok){
  skip_ws(s,i); size_t j=i; while(j<s.size() && (std::isdigit((unsigned char)s[j])||s[j]=='.'||s[j]=='-'||s[j]=='+')) ++j;
  if(j==i){ ok=false; return 0.0; } ok=true; return std::stod(s.substr(i, j-i));
}
std::optional<LogRecord> parse_ndjson_line(const std::string& line, std::string& err){
  size_t i=0; if(!match(line,i,'{')){ err="expected {"; return std::nullopt; }
  LogRecord r{}; bool ok=true;
  while(true){
    skip_ws(line,i); if(i<line.size() && line[i]=='}'){ ++i; break; }
    std::string key=parse_string(line,i,ok); if(!ok){ err="bad key"; return std::nullopt; }
    if(!match(line,i,':')){ err="expected :"; return std::nullopt; }
    if(key=="ts"){ double v=parse_number(line,i,ok); if(!ok){ std::string s=parse_string(line,i,ok); if(ok){ std::string e; r.ts = parse_timestamp(s,e); if(r.ts<0){ err=e; return std::nullopt; } } else { err="bad ts"; return std::nullopt; } } else r.ts=(long long)v; }
    else if(key=="src_ip"){ r.src_ip=parse_string(line,i,ok); if(!ok){ err="bad src_ip"; return std::nullopt; } }
    else if(key=="dst_ip"){ r.dst_ip=parse_string(line,i,ok); if(!ok){ err="bad dst_ip"; return std::nullopt; } }
    else if(key=="dst_port"){ double v=parse_number(line,i,ok); if(!ok){ err="bad dst_port"; return std::nullopt; } r.dst_port=(int)v; }
    else if(key=="protocol"){ r.protocol=parse_string(line,i,ok); if(!ok){ err="bad protocol"; return std::nullopt; } }
    else if(key=="action"){ r.action=parse_string(line,i,ok); if(!ok){ err="bad action"; return std::nullopt; } }
    else if(key=="status"){ r.status=parse_string(line,i,ok); if(!ok){ err="bad status"; return std::nullopt; } }
    else if(key=="bytes"){ double v=parse_number(line,i,ok); if(!ok){ err="bad bytes"; return std::nullopt; } r.bytes=(long long)v; }
    else if(key=="username"){ r.username=parse_string(line,i,ok); if(!ok){ err="bad username"; return std::nullopt; } }
    else { bool lok=true; std::string _s=parse_string(line,i,lok); if(!lok){ bool oknum=True; parse_number(line,i,oknum);} }
    skip_ws(line,i); if(i<line.size() && line[i]==','){ ++i; continue; }
  }
  return r;
}
} // namespace neonsec
