// SPDX-License-Identifier: Apache-2.0
#include "neonsec/config.hpp"
#include <fstream>
#include <sstream>
#include <cctype>
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
std::optional<Config> load_config_json(const std::string& path, std::string& err){
  std::ifstream f(path); if(!f){ err="cannot open config"; return std::nullopt; }
  std::ostringstream ss; ss<<f.rdbuf(); std::string s=ss.str(); size_t i=0; Config c; bool ok=true;
  if(!match(s,i,'{')){ err="expected {"; return std::nullopt; }
  while(true){
    skip_ws(s,i); if(i<s.size() && s[i]=='}'){ ++i; break; }
    std::string key=parse_string(s,i,ok); if(!ok){ err="bad key"; return std::nullopt; }
    if(!match(s,i,':')){ err="expected :"; return std::nullopt; }
    if(key=="input") c.input=parse_string(s,i,ok);
    else if(key=="input_format") c.input_format=parse_string(s,i,ok);
    else if(key=="format") c.format=parse_string(s,i,ok);
    else if(key=="output") c.output=parse_string(s,i,ok);
    else if(key=="window"){ double v=parse_number(s,i,ok); c.wcfg.span_sec=(int)v; }
    else if(key=="max_records_per_key"){ double v=parse_number(s,i,ok); c.wcfg.max_records_per_key=(int)v; }
    else if(key=="metrics") c.metrics=parse_string(s,i,ok);
    else if(key=="sarif") c.sarif=parse_string(s,i,ok);
    else if(key=="threads"){ double v=parse_number(s,i,ok); c.threads=(int)v; }
    else if(key=="sample"){ double v=parse_number(s,i,ok); c.sample=(int)v; }
    else if(key=="plugins"){
      if(!match(s,i,'[')) { err="plugins must be array"; return std::nullopt; }
      while(true){ skip_ws(s,i); if(i<s.size() && s[i]==']'){ ++i; break; } c.plugins.push_back(parse_string(s,i,ok)); if(!ok){ err="bad plugin string"; return std::nullopt; } skip_ws(s,i); if(i<s.size() && s[i]==','){ ++i; continue; } }
    }
    else if(key=="thresholds"){
      if(!match(s,i,'{')){ err="thresholds must be object"; return std::nullopt; }
      while(true){
        skip_ws(s,i); if(i<s.size() && s[i]=='}'){ ++i; break; }
        std::string k=parse_string(s,i,ok); if(!match(s,i,':')){ err="expected :"; return std::nullopt; }
        double v=parse_number(s,i,ok); if(!ok){ err="bad number"; return std::nullopt; }
        if(k=="portscan_unique_ports") c.dcfg.portscan_unique_ports=(int)v;
        else if(k=="bruteforce_failures") c.dcfg.bruteforce_failures=(int)v;
        else if(k=="ddos_events") c.dcfg.ddos_events=(int)v;
        else if(k=="ddos_unique_sources") c.dcfg.ddos_unique_sources=(int)v;
        else if(k=="anomaly_z") c.dcfg.anomaly_z=v;
        skip_ws(s,i); if(i<s.size() && s[i]==','){ ++i; continue; }
      }
    } else {
      size_t save=i; bool s_ok=true; std::string _s=parse_string(s,i,s_ok);
      if(!s_ok){ i=save; bool n_ok=true; parse_number(s,i,n_ok); }
    }
    skip_ws(s,i); if(i<s.size() && s[i]==','){ ++i; continue; }
  }
  return c;
}
void merge_cli_over_config(Config& cfg, const Config& cli){
  auto repl=[&](std::string& dst, const std::string& src){ if(!src.empty()) dst=src; };
  repl(cfg.input, cli.input); repl(cfg.input_format, cli.input_format); repl(cfg.format, cli.format); repl(cfg.output, cli.output);
  if(cli.wcfg.span_sec) cfg.wcfg.span_sec=cli.wcfg.span_sec;
  if(cli.wcfg.max_records_per_key) cfg.wcfg.max_records_per_key=cli.wcfg.max_records_per_key;
  if(cli.dcfg.portscan_unique_ports) cfg.dcfg.portscan_unique_ports=cli.dcfg.portscan_unique_ports;
  if(cli.dcfg.bruteforce_failures) cfg.dcfg.bruteforce_failures=cli.dcfg.bruteforce_failures;
  if(cli.dcfg.ddos_events) cfg.dcfg.ddos_events=cli.dcfg.ddos_events;
  if(cli.dcfg.ddos_unique_sources) cfg.dcfg.ddos_unique_sources=cli.dcfg.ddos_unique_sources;
  if(cli.dcfg.anomaly_z!=0.0) cfg.dcfg.anomaly_z=cli.dcfg.anomaly_z;
  if(!cli.plugins.empty()) cfg.plugins=cli.plugins;
  repl(cfg.metrics, cli.metrics); repl(cfg.sarif, cli.sarif);
  if(cli.threads) cfg.threads=cli.threads;
  if(cli.sample) cfg.sample=cli.sample;
}
} // namespace neonsec
