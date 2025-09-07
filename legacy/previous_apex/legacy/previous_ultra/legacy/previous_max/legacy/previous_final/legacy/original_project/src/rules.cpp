// SPDX-License-Identifier: Apache-2.0
#include "neonsec/rules.hpp"
#include <fstream>
#include <sstream>
#include <cctype>
#include <regex>
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
static bool parse_conditions_array(const std::string& s, size_t& i, std::vector<Condition>& out, std::string& err){
  if(!match(s,i,'[')){ err="expected ["; return false; }
  bool ok=true;
  while(true){
    skip_ws(s,i); if(i<s.size() && s[i]==']'){ ++i; break; }
    if(!match(s,i,'{')){ err="expected { in condition"; return false; }
    std::string field, op, value;
    while(true){
      skip_ws(s,i); if(i<s.size() && s[i]=='}'){ ++i; break; }
      std::string k=parse_string(s,i,ok); if(!match(s,i,':')){ err="expected :"; return false; }
      if(k=="field") field=parse_string(s,i,ok);
      else if(k=="op") op=parse_string(s,i,ok);
      else if(k=="value") value=parse_string(s,i,ok);
      skip_ws(s,i); if(i<s.size() && s[i]==','){ ++i; continue; }
    }
    CmpOp cop = CmpOp::EQ; if(op=="ne") cop=CmpOp::NE; else if(op==">=") cop=CmpOp::GE; else if(op==">") cop=CmpOp::GT; else if(op=="<=") cop=CmpOp::LE; else if(op=="<") cop=CmpOp::LT; else if(op=="regex") cop=CmpOp::REGEX;
    out.push_back(Condition{field, cop, value});
    skip_ws(s,i); if(i<s.size() && s[i]==','){ ++i; continue; }
  }
  return true;
}
std::optional<RulesConfig> load_rules_json(const std::string& path, std::string& err){
  std::ifstream f(path); if(!f){ err="cannot open rules"; return std::nullopt; }
  std::ostringstream ss; ss<<f.rdbuf(); std::string s=ss.str(); size_t i=0;
  if(!match(s,i,'{')){ err="expected {"; return std::nullopt; }
  RulesConfig rc;
  while(true){
    skip_ws(s,i); if(i<s.size() && s[i]=='}'){ ++i; break; }
    bool ok=true; std::string key=parse_string(s,i,ok); if(!ok){ err="bad key"; return std::nullopt; }
    if(!match(s,i,':')){ err="expected :"; return std::nullopt; }
    if(key=="rules"){
      if(!match(s,i,'[')){ err="rules must be array"; return std::nullopt; }
      while(true){
        skip_ws(s,i); if(i<s.size() && s[i]==']'){ ++i; break; }
        if(!match(s,i,'{')){ err="expected { in rule"; return std::nullopt; }
        Rule r; r.within_sec=60;
        while(true){
          skip_ws(s,i); if(i<s.size() && s[i]=='}'){ ++i; break; }
          std::string k=parse_string(s,i,ok); if(!match(s,i,':')){ err="expected :"; return std::nullopt; }
          if(k=="name") r.name=parse_string(s,i,ok);
          else if(k=="when"){ if(!parse_conditions_array(s,i,r.when,err)) return std::nullopt; }
          else if(k=="group_by") r.group_by=parse_string(s,i,ok);
          else if(k=="within_sec"){ double v=parse_number(s,i,ok); r.within_sec=(int)v; }
          else if(k=="count"){ if(!match(s,i,'{')){ err="count must be object"; return std::nullopt; } std::string op; int val=0; while(true){ skip_ws(s,i); if(i<s.size() && s[i]=='}'){ ++i; break; } std::string kk=parse_string(s,i,ok); if(!match(s,i,':')){ err="expected :"; return std::nullopt; } if(kk=="op") op=parse_string(s,i,ok); else if(kk=="value"){ double v=parse_number(s,i,ok); val=(int)v; } skip_ws(s,i); if(i<s.size() && s[i]==','){ ++i; continue; } } if(op==">=") r.count_ge=val; }
          else if(k=="sum_bytes"){ if(!match(s,i,'{')){ err="sum_bytes must be object"; return std::nullopt; } std::string op; long long val=0; while(true){ skip_ws(s,i); if(i<s.size() && s[i]=='}'){ ++i; break; } std::string kk=parse_string(s,i,ok); if(!match(s,i,':')){ err="expected :"; return std::nullopt; } if(kk=="op") op=parse_string(s,i,ok); else if(kk=="value"){ double v=parse_number(s,i,ok); val=(long long)v; } skip_ws(s,i); if(i<s.size() && s[i]==','){ ++i; continue; } } if(op==">=") r.sum_bytes_ge=val; }
          else if(k=="emit"){ if(!match(s,i,'{')){ err="emit must be object"; return std::nullopt; } while(true){ skip_ws(s,i); if(i<s.size() && s[i]=='}'){ ++i; break; } std::string kk=parse_string(s,i,ok); if(!match(s,i,':')){ err="expected :"; return std::nullopt; } if(kk=="type") r.emit_type=parse_string(s,i,ok); else if(kk=="details") r.emit_details=parse_string(s,i,ok); skip_ws(s,i); if(i<s.size() && s[i]==','){ ++i; continue; } } }
          else { size_t save=i; bool s_ok=true; std::string _s=parse_string(s,i,s_ok); if(!s_ok){ i=save; bool n_ok=true; parse_number(s,i,n_ok); }
          }
          skip_ws(s,i); if(i<s.size() && s[i]==','){ ++i; continue; }
        }
        rc.rules.push_back(std::move(r));
        skip_ws(s,i); if(i<s.size() && s[i]==','){ ++i; continue; }
      }
    } else {
      size_t save=i; bool s_ok=true; std::string _s=parse_string(s,i,s_ok); if(!s_ok){ i=save; bool n_ok=true; parse_number(s,i,n_ok); }
    }
    skip_ws(s,i); if(i<s.size() && s[i]==','){ ++i; continue; }
  }
  return rc;
}
static bool cmp_value(CmpOp op, const std::string& a, const std::string& b){
  switch(op){
    case CmpOp::EQ: return a==b;
    case CmpOp::NE: return a!=b;
    case CmpOp::GE: try{ return std::stod(a) >= std::stod(b); }catch(...){ return a>=b; }
    case CmpOp::GT: try{ return std::stod(a) > std::stod(b); }catch(...){ return a>b; }
    case CmpOp::LE: try{ return std::stod(a) <= std::stod(b); }catch(...){ return a<=b; }
    case CmpOp::LT: try{ return std::stod(a) < std::stod(b); }catch(...){ return a<b; }
    case CmpOp::REGEX: try{ return std::regex_search(a, std::regex(b)); } catch(...){ return false; }
  } return false;
}
bool RulesEngine::matches(const Rule& r, const LogRecord& rec) const {
  for(const auto& c: r.when){
    std::string val;
    if(c.field=="action") val=rec.action;
    else if(c.field=="status") val=rec.status;
    else if(c.field=="protocol") val=rec.protocol;
    else if(c.field=="src_ip") val=rec.src_ip;
    else if(c.field=="dst_ip") val=rec.dst_ip;
    else if(c.field=="username") val=rec.username;
    else if(c.field=="dst_port") val=std::to_string(rec.dst_port);
    else if(c.field=="bytes") val=std::to_string(rec.bytes);
    else if(c.field=="ts") val=std::to_string(rec.ts);
    if(!cmp_value(c.op, val, c.value)) return false;
  }
  return true;
}
std::string RulesEngine::key_for(const Rule& r, const LogRecord& rec) const {
  if(r.group_by=="src_ip") return rec.src_ip;
  if(r.group_by=="dst_ip") return rec.dst_ip;
  if(r.group_by=="username") return rec.username;
  if(r.group_by=="protocol") return rec.protocol;
  if(r.group_by=="dst_port") return std::to_string(rec.dst_port);
  return "";
}
std::vector<Finding> RulesEngine::feed(const LogRecord& r){
  std::vector<Finding> out;
  for(const auto& rule : rules_){
    if(!matches(rule, r)) continue;
    win_.add(r, rule.name + ":" + key_for(rule, r));
    win_.evict(r.ts);
    const auto& dq = win_.get(rule.name + ":" + key_for(rule, r));
    int count = (int)dq.size();
    long long sum_bytes = 0; for(auto& x: dq) sum_bytes += x.bytes;
    bool ok=true;
    if(rule.count_ge>0) ok &= (count >= rule.count_ge);
    if(rule.sum_bytes_ge>0) ok &= (sum_bytes >= rule.sum_bytes_ge);
    if(ok){ out.push_back(Finding{rule.emit_type, key_for(rule, r), rule.emit_details, r.ts}); }
  } return out;
}
} // namespace neonsec
