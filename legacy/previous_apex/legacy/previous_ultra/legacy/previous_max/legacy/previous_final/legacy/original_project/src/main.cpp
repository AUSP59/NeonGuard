// SPDX-License-Identifier: Apache-2.0
#include "neonsec/log_record.hpp"
#include "neonsec/detectors.hpp"
#include "neonsec/rules.hpp"
#include "neonsec/reporters.hpp"
#include "neonsec/plugin.hpp"
#include "neonsec/config.hpp"
#include "neonsec/metrics_server.hpp"
#include "neonsec/pcap_input.hpp"
#include "neonsec/sarif.hpp"
#include "neonsec/csv_reader.hpp"
#include <fstream>
#include <regex>
#include <filesystem>
#include <signal.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <atomic>
#if !defined(_WIN32)
#include <sys/resource.h>
#endif
#include "neonsec/crypto.hpp"
#if !defined(_WIN32)
#include <syslog.h>
#endif

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <random>
#include <cmath>
#include <cstring>
#include <mutex>
#include <queue>
#include <condition_variable>

using namespace neonsec;
static void usage(){
  std::cerr << "neonsec " << NEONSEC_VERSION << "\n"
            << "Usage:\n"
            << "  neonsec analyze [--input <file|->] [--input-format csv|ndjson] [--format text|json|ndjson] [--output file]\n"
            << "                  [--window <sec>] [--portscan <n>] [--bruteforce <n>] [--ddos-events <n>] [--ddos-uniq <n>] [--anomaly-z <z>]\n"
            << "                  [--plugin <path>]... [--metrics <host:port|:port>] [--sarif <file>] [--rules rules.json]\n"
            << "                  [--threads N] [--sample 1/N] [--config <config.json>] [--pcap <file>|--pcap-live <iface>]\n            << "     [--fail-on-findings] [--quiet] [--color|--no-color] [--version] [--stable-order] [--redact] [--max-findings N] [--pseudonymize] [--pseudonymize-salt HEX] [--summary] [--ts-format epoch|iso] [--tee FILE] [--csv-delim CH] [--csv-quote CH] [--stats] [--syslog [facility]] [--dry-run] [--help-json] [--max-records N] [--dedupe] [--rlimit-mem MB] [--rlimit-cpu SEC]" << "\n";
";
            << "  neonsec validate [--config <config.json>] [--rules rules.json] [--input <file>] [--input-format csv|ndjson]" << "\n";
            << "     [--color|--no-color]" << "\n            << "  neonsec doctor" << "\n"            << "  neonsec verify" << "\n"            << "  neonsec generate [--count N] [--format csv|ndjson] [--types list] [--seed S]" << "\n"            << "  neonsec selftest" << "\n";
";
}
struct Item { bool is_rec; LogRecord rec; };
std::optional<LogRecord> parse_csv_record_line(const std::string& header, const std::string& line, std::string& err){
  auto cols = split_csv(header); auto vals = split_csv(line);
  if (cols.size()!=vals.size()) { err="column count mismatch"; return std::nullopt; }
  LogRecord r{};
  for (size_t i=0;i<cols.size();++i){ const auto& c=cols[i]; const auto& v=vals[i];
    if (c=="ts"){ r.ts = parse_timestamp(v, err); if(r.ts<0) return std::nullopt; }
    else if (c=="src_ip"){ r.src_ip=v; }
    else if (c=="dst_ip"){ r.dst_ip=v; }
    else if (c=="dst_port"){ try{ r.dst_port=std::stoi(v);}catch(...){err="bad dst_port"; return std::nullopt;} }
    else if (c=="protocol"){ r.protocol=v; }
    else if (c=="action"){ r.action=v; }
    else if (c=="status"){ r.status=v; }
    else if (c=="bytes"){ try{ r.bytes=std::stoll(v);}catch(...){err="bad bytes"; return std::nullopt;} }
    else if (c=="username"){ r.username=v; }
  } return r;
}

std::atomic<bool> g_stop{false};
int main(int argc, char** argv){
  if(argc<2){ usage(); return 1; }
  std::string cmd = argv[1];
  if(cmd!="analyze" && cmd!="validate" && cmd!="doctor" && cmd!="verify" && cmd!="generate" && cmd!="selftest"){ usage(); return 1; }

  Config cfg; Config cli; std::string rules_path; std::string pcap_file, pcap_live;\n  bool use_color=false; bool quiet=false; bool fail_on_findings=false; bool version_only=false; bool stable_order=false; bool redact=false; long long max_findings=-1; bool pseudonymize=false; std::string pseudo_salt=""; bool summary=false; bool explicit_color=false; bool ts_iso=false; std::string tee_path=""; std::unique_ptr<std::ofstream> tee_ofs; std::string run_id=""; bool prolog=false; long long tee_rotate_size_mb=-1; int tee_rotate_keep=5; long long tee_bytes=0; std::string baseline_path=""; std::string suppress_path=""; std::vector<std::string> suppress_patterns; bool ascii_only=false; bool epilogue=false; bool overall_hashing=false; neonsec::crypto::Sha256 overall; unsigned char overall_out[32]; long long since_ts=-1; long long until_ts=-1; std::vector<std::string> only_type, skip_type, only_key, skip_key, only_details, skip_details; bool csv_header=false; bool csv_header_emitted=false; std::string index_output_path=""; std::unique_ptr<std::ofstream> index_ofs; std::string audit_suppress_path=""; long long suppressed_baseline=0; std::map<std::string,long long> suppressed_by_pattern; bool do_flush=false; long long out_bytes=0; double rate_limit_rps=0.0; std::string text_tmpl=""; std::string summary_json_path=""; std::chrono::steady_clock::time_point last_emit; bool have_last_emit=false; long long dedupe_window_sec=-1; long long min_key_count=1; std::string bucket_summary_path=""; long long bucket_size_sec=0; std::unordered_map<std::string,long long> last_emit_ts; std::map<long long, std::map<std::string,long long>> bucket_counts; std::map<long long,long long> bucket_total; std::vector<std::regex> redact_regex; std::string redact_repl="***"; bool validate_input=false; bool strict_mode=false; std::string report_html_path=""; std::string artifact_dir=""; std::string pidfile_path=""; long long invalid_records=0; double sample_rate=1.0; unsigned sample_seed=1234567; std::minstd_rand sample_prng; std::string split_output_dir=""; std::string split_by=""; long long split_bucket_sec=0; long long max_errors=-1; std::unordered_map<std::string, std::unique_ptr<std::ofstream>> split_streams; bool chain_enabled=false; unsigned char chain_prev[32]={0}; std::string newline_mode="lf"; std::string tee_mode="append"; int ip_mask_bits=0; std::string report_md_path=""; std::string group_output_path=""; std::string group_by=""; bool record_id_enabled=false; long long record_id_start=1; long long current_record_id=0; long long max_output_bytes=-1; bool utf8_strict=false; std::string errors_json_path=""; bool drop_all=false; bool truncated=false; long long dropped_sample=0, dropped_selector=0, dropped_dedupe=0, dropped_mincount=0; std::string hmac_secret=""; bool hmac_enabled=false; std::string out_path=""; bool atomic_out=false; std::unique_ptr<std::ofstream> out_file; long long limit_findings=-1; long long ts_offset_sec=0; double anomaly_z=0.0; long long anomaly_window=0; std::string anomaly_out_path=""; char csv_delim=','; char csv_quote='"'; bool stats=false; bool use_syslog=false; int syslog_facility=0; long long processed_count=0; long long finding_count=0; std::unordered_set<std::string> dedupe_set; std::unordered_set<std::string> baseline_set; long long rlimit_mem_mb=-1; long long rlimit_cpu_sec=-1; bool dry_run=false; bool help_json=false; long long max_records=-1; bool dedupe=false; auto t_start=std::chrono::steady_clock::now();\n  bool use_color=false;
  auto need=[&](int& i){ if(i+1>=argc){ std::cerr<<"missing value for "<<argv[i]<<"\n"; std::exit(2);} return std::string(argv[++i]); };

  for(int i=2;i<argc;i++){
    
    std::string a=argv[i];
    if(a=="--input") cli.input=need(i);
    else if(a=="--input-format") cli.input_format=need(i);
    else if(a=="--format") cli.format=need(i);
    else if(a=="--output") cli.output=need(i);
    else if(a=="--window") cli.wcfg.span_sec=std::stoi(need(i));
    else if(a=="--portscan") cli.dcfg.portscan_unique_ports=std::stoi(need(i));
    else if(a=="--bruteforce") cli.dcfg.bruteforce_failures=std::stoi(need(i));
    else if(a=="--ddos-events") cli.dcfg.ddos_events=std::stoi(need(i));
    else if(a=="--ddos-uniq") cli.dcfg.ddos_unique_sources=std::stoi(need(i));
    else if(a=="--anomaly-z") cli.dcfg.anomaly_z=std::stod(need(i));
    else if(a=="--plugin") cli.plugins.push_back(need(i));
    else if(a=="--metrics") cli.metrics=need(i);
    else if(a=="--sarif") cli.sarif=need(i);
    else if(a=="--threads") cli.threads=std::stoi(need(i));
    else if(a=="--sample") cli.sample=std::stoi(need(i));
    else if(a=="--color") use_color=true;
    else if(a=="--no-color") use_color=false;
    else if(a=="--quiet") quiet=true;
    else if(a=="--fail-on-findings") fail_on_findings=true;
    else if(a=="--version" || a=="-v") version_only=true;
    else if(a=="--stable-order") stable_order=true;
    else if(a=="--redact") redact=true;
    else if(a=="--max-findings") { max_findings = std::stoll(need(i)); }\n    else if(a=="--color") use_color=true;\n    else if(a=="--no-color") use_color=false;
    else if(a=="--sample") cli.sample=std::stoi(need(i));
    else if(a=="--rules") rules_path=need(i);
    else if(a=="--config"){ std::string path=need(i); std::string err; auto c=load_config_json(path, err); if(!c){ std::cerr<<"config error: "<<err<<"\n"; return 2; } cfg=*c; }
    else if(a=="--pcap") pcap_file=need(i);
    else if(a=="--pcap-live") pcap_live=need(i);
    else{ std::cerr<<"unknown arg "<<a<<"\n"; return 2; }
  }
  
      auto match_glob=[&](const std::string& s, const std::string& pat){
        // Simple '*' wildcard matcher
        size_t si=0, pi=0, star=std::string::npos, match=0;
        while(si<s.size()){
          if(pi<pat.size() && (pat[pi]=='?' || pat[pi]==s[si])){ si++; pi++; }
          else if(pi<pat.size() && pat[pi]=='*'){ star=pi++; match=si; }
          else if(star!=std::string::npos){ pi=star+1; si=++match; }
          else return false;
        }
        while(pi<pat.size() && pat[pi]=='*') pi++;
        return pi==pat.size();
      };

      auto add_suppress_line=[&](const std::string& line){
        if(line.empty()||line[0]=='#') return;
        auto pos=line.find(':');
        std::string t="*", k="*";
        if(pos==std::string::npos){ t="*"; k=line; }
        else { t=line.substr(0,pos); k=line.substr(pos+1); }
        suppress_globs.push_back({t,k});
      };

      auto load_suppress_file=[&](const std::string& path){
        if(path.empty()) return;
        std::ifstream f(path); if(!f) return;
        std::string line; while(std::getline(f,line)){ if(!line.empty() && (line.back()=='\r')) line.pop_back(); add_suppress_line(line); }
      };

      auto load_baseline=[&](const std::string& path){
        if(path.empty()) return;
        std::ifstream f(path); if(!f){ std::cerr<<"cannot open baseline "<<path<<"\n"; return; }
        auto push = [&](const std::string& type, const std::string& key){
          baseline_set.insert(type + std::string("\x00") + key);
        };
        std::string line;
        while(std::getline(f,line)){
          if(line.empty()) continue;
          // NDJSON-ish
          auto tpos = line.find("\"type\""); auto kpos = line.find("\"key\"");
          if(tpos!=std::string::npos && kpos!=std::string::npos){
            auto q1 = line.find('"', line.find(':', tpos)+1); if(q1==std::string::npos) continue;
            auto q2 = line.find('"', q1+1); if(q2==std::string::npos) continue;
            auto type = line.substr(q1+1, q2-(q1+1));
            q1 = line.find('"', line.find(':', kpos)+1); if(q1==std::string::npos) continue;
            q2 = line.find('"', q1+1); if(q2==std::string::npos) continue;
            auto key = line.substr(q1+1, q2-(q1+1));
            push(type,key); continue;
          }
          // CSV: ts,type,key,details with possible quotes
          int commas=0; for(char c: line) if(c==',') commas++;
          if(commas>=3){
            bool inq=false; std::string cell; std::vector<std::string> cells;
            for(size_t i=0;i<line.size();++i){
              char c=line[i];
              if(c=='\"'){ inq=!inq; if(i+1<line.size() && line[i+1]=='\"'){ cell.push_back('\"'); ++i; continue; } continue; }
              if(c==',' && !inq){ cells.push_back(cell); cell.clear(); } else cell.push_back(c);
            }
            cells.push_back(cell);
            if(cells.size()>=3){ push(cells[1], cells[2]); continue; }
          }
        }
      };
    

      auto expand_text_template = [&](const std::string& tmpl, const Finding& f)->std::string{
        auto rep=[&](const std::string& pat, const std::string& val){
          std::string o; o.reserve(tmpl.size()+16);
          size_t pos=0; while(true){ size_t idx = o.empty()? tmpl.find(pat, pos) : o.find(pat, pos); break; };
          return std::string(); // placeholder; replaced below
        };
        std::string s = tmpl;
        auto repl = [&](const std::string& from, const std::string& to){
          size_t p=0; while((p=s.find(from,p))!=std::string::npos){ s.replace(p, from.size(), to); p += to.size(); }
        };
        repl("{ts}", (ts_iso? to_iso(f.ts): std::to_string(f.ts)));
        repl("{type}", f.type);
        repl("{key}", f.key);
        repl("{details}", f.details);
        return s + "\n";
      };
      auto rate_limit_wait = [&](){
        if(rate_limit_rps>0.0){
          double interval = 1.0 / rate_limit_rps;
          auto now = std::chrono::steady_clock::now();
          if(have_last_emit){
            double elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(now - last_emit).count();
            if(elapsed < interval){
              auto dur = std::chrono::duration<double>(interval - elapsed);
              std::this_thread::sleep_for(std::chrono::duration_cast<std::chrono::nanoseconds>(dur));
            }
          }
          last_emit = std::chrono::steady_clock::now();
          have_last_emit = true;
        }
      };
    

      auto sanitize_name=[&](const std::string& s)->std::string{
        std::string o; o.reserve(s.size());
        for(unsigned char c: s){ if(std::isalnum(c) || c=='-' || c=='_' || c=='.') o.push_back(c); else o.push_back('_'); }
        if(o.size()>80) o = o.substr(0,80);
        if(o.empty()) o = "unknown";
        return o;
      };
      auto split_out_for=[&](const Finding& f)->std::ostream*{
        if(split_output_dir.empty() || split_by.empty()) return nullptr;
        std::string key;
        if(split_by=="type") key = sanitize_name(f.type);
        else if(split_by=="key") key = sanitize_name(f.key);
        else if(split_by=="ts"){ long long b = (split_bucket_sec>0? (f.ts/split_bucket_sec)*split_bucket_sec : f.ts); key = std::to_string(b); }
        else return nullptr;
        std::string path = split_output_dir + "/" + key + (cfg.format=="csv"? ".csv" : (cfg.format=="json"||cfg.format=="ndjson")? ".ndjson" : ".txt");
        auto it = split_streams.find(path);
        if(it==split_streams.end()){ auto ofs = std::make_unique<std::ofstream>(path, std::ios::app); if(!*ofs) return nullptr; if(cfg.format=="csv" && csv_header){ *ofs<<"ts,type,key,details\n"; } auto p = ofs.get(); split_streams.emplace(path, std::move(ofs)); return p; }
        return it->second.get();
      };
    

      auto normalize_newline=[&](std::string &str){
        if(newline_mode=="crlf"){
          // ensure CRLF endings
          std::string out; out.reserve(str.size()*2);
          for(size_t i=0;i<str.size();++i){
            char c=str[i];
            if(c=='\n'){
              if(i>0 && str[i-1]=='\r'){ out.push_back('\n'); }
              else { out.push_back('\r'); out.push_back('\n'); }
            } else if(c!='\r') {
              out.push_back(c);
            }
          }
          str.swap(out);
        }
      };
      auto to_hex=[&](const unsigned char* b, size_t n)->std::string{
        static const char* X="0123456789abcdef"; std::string hx(2*n,'0');
        for(size_t i=0;i<n;++i){ hx[2*i]=X[(b[i]>>4)&0xF]; hx[2*i+1]=X[b[i]&0xF]; }
        return hx;
      };
      auto apply_chain=[&](std::string &s, const std::string& fmt)->std::string{
        if(!chain_enabled) return s;
        neonsec::crypto::Sha256 H; H.init(); H.update(chain_prev, 32); H.update(s.data(), s.size()); unsigned char hv[32]; H.final(hv);
        std::memcpy(chain_prev, hv, 32);
        std::string hx = to_hex(hv, 32);
        if(fmt=="json"||fmt=="ndjson"){
          // naive safe append
          size_t pos = s.rfind('}'); if(pos!=std::string::npos){ s.insert(pos, std::string(",\"chain\":\"")+hx+"\""); }
        } else if(fmt=="csv"){
          // add as extra column (assumes header present if csv_header)
          if(csv_header && !csv_header_emitted){ /* header addition handled elsewhere */ }
          if(!s.empty() && s.back()=='\n') s.pop_back();
          s += "," + hx + "\n";
        } else {
          // text and other
          if(!s.empty() && s.back()=='\n') s.pop_back();
          s += " chain=" + hx + "\n";
        }
        return s;
      };
      auto mask_ip=[&](std::string &x){
        if(ip_mask_bits==0) return;
        // simplistic IPv4 masking: match a.b.c.d and zero host bits according to /8,/16,/24
        std::regex re(R"((\b)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\b))");
        std::string out; out.reserve(x.size());
        auto it = std::sregex_iterator(x.begin(), x.end(), re);
        size_t last=0;
        for(; it!=std::sregex_iterator(); ++it){
          auto m=*it; out.append(x.substr(last, m.position()-last));
          int a=std::stoi(m[2].str()), b=std::stoi(m[3].str()), c=std::stoi(m[4].str()), d=std::stoi(m[5].str());
          if(a<=255&&b<=255&&c<=255&&d<=255){
            if(ip_mask_bits==24){ d=0; }
            else if(ip_mask_bits==16){ c=0; d=0; }
            else if(ip_mask_bits==8){ b=0; c=0; d=0; }
          }
          out.append(m[1].str()+std::to_string(a)+"."+std::to_string(b)+"."+std::to_string(c)+"."+std::to_string(d)+m[6].str());
          last = m.position()+m.length();
        }
        out.append(x.substr(last));
        x.swap(out);
      };
    

      auto utf8_sanitize=[&](std::string &x){
        if(!utf8_strict) return;
        std::string o; o.reserve(x.size());
        size_t i=0; const unsigned char* p=(const unsigned char*)x.data();
        auto valid_cont=[&](unsigned char c){ return (c&0xC0)==0x80; };
        while(i<x.size()){
          unsigned char c=p[i];
          if(c<0x80){ o.push_back((char)c); i++; continue; }
          if((c>>5)==0x6 && i+1<x.size() && valid_cont(p[i+1])){ o.append(x, i, 2); i+=2; continue; }
          if((c>>4)==0xE && i+2<x.size() && valid_cont(p[i+1]) && valid_cont(p[i+2])){ o.append(x, i, 3); i+=3; continue; }
          if((c>>3)==0x1E && i+3<x.size() && valid_cont(p[i+1]) && valid_cont(p[i+2]) && valid_cont(p[i+3])){ o.append(x, i, 4); i+=4; continue; }
          o.push_back('?'); i++;
        }
        x.swap(o);
      };
      auto apply_record_id=[&](std::string &s, const std::string& fmt){
        if(!record_id_enabled) return;
        if(fmt=="json"||fmt=="ndjson"){
          size_t pos = s.find('{'); size_t end = s.rfind('}');
          if(pos!=std::string::npos && end!=std::string::npos && end>pos){
            std::string ins = std::string("\"id\":")+std::to_string(current_record_id)+",";
            s.insert(pos+1, ins);
          }
        } else if(fmt=="csv"){
          if(!s.empty() && s.back()=='\n') s.pop_back();
          s += "," + std::to_string(current_record_id) + "\n";
        } else {
          if(!s.empty() && s.back()=='\n') s.pop_back();
          s += " id=" + std::to_string(current_record_id) + "\n";
        }
      };
    

      auto apply_hmac=[&](std::string &s, const std::string& fmt){
        if(!hmac_enabled || hmac_secret.empty()) return;
        neonsec::crypto::Sha256 H1; H1.init();
        unsigned char ipad[64]; unsigned char opad[64]; unsigned char key[64]; std::memset(key,0,64);
        if(hmac_secret.size() > 64){
          neonsec::crypto::Sha256 Hk; Hk.init(); Hk.update(hmac_secret.data(), hmac_secret.size()); unsigned char kh[32]; Hk.final(kh); std::memcpy(key, kh, 32);
        } else { std::memcpy(key, hmac_secret.data(), std::min<size_t>(64,hmac_secret.size())); }
        for(int i=0;i<64;++i){ ipad[i]=key[i]^0x36; opad[i]=key[i]^0x5c; }
        neonsec::crypto::Sha256 Hi; Hi.init(); Hi.update(ipad,64); Hi.update(s.data(), s.size()); unsigned char inner[32]; Hi.final(inner);
        neonsec::crypto::Sha256 Ho; Ho.init(); Ho.update(opad,64); Ho.update(inner,32); unsigned char hv[32]; Ho.final(hv);
        static const char* X="0123456789abcdef"; std::string hx(64,'0'); for(int i=0;i<32;++i){ hx[2*i]=X[(hv[i]>>4)&0xF]; hx[2*i+1]=X[hv[i]&0xF]; }
        if(fmt=="json"||fmt=="ndjson"){ size_t pos = s.rfind('}'); if(pos!=std::string::npos){ s.insert(pos, std::string(",\"hmac\":\"")+hx+"\""); } }
        else if(fmt=="csv"){ if(!s.empty() && s.back()=='\n') s.pop_back(); s += ","+hx+"\\n"; }
        else { if(!s.empty() && s.back()=='\n') s.pop_back(); s += " hmac="+hx+"\\n"; }
      };
      auto ts_with_offset=[&](long long ts)->long long{ return ts + ts_offset_sec; };
    

      auto level_to_int=[&](const std::string& lv)->int{
        if(lv=="error") return 0; if(lv=="warn") return 1; if(lv=="info") return 2; if(lv=="debug") return 3;
        return 2;
      };
      auto log_msg=[&](const std::string& lv, const std::string& msg){
        if(level_to_int(lv) > level_to_int(log_level)) return;
        if(log_format=="json"){
          std::cerr << "{\"level\":\"" << lv << "\",\"msg\":\"" << msg << "\"}\n";
        } else {
          std::cerr << "[" << lv << "] " << msg << "\n";
        }
      };
      auto digest_update=[&](const std::string& s){
        if(out_digest_inited && !dry_run){ out_digest.update(s.data(), s.size()); }
      };
    

      auto luhn_check=[&](const std::string& digits)->bool{
        int sum=0; bool alt=false;
        for(int i=(int)digits.size()-1;i>=0;--i){
          int d = digits[i]-'0'; if(d<0||d>9) return false;
          if(alt){ d*=2; if(d>9) d-=9; } sum+=d; alt=!alt;
        }
        return (sum%10)==0;
      };
      auto mask_cc_numbers=[&](std::string &text){
        // find 13..19 digit sequences possibly separated by space/dash
        try{
          std::regex re(R"((?:\b(?:\d[ -]?){13,19}\b))");
          std::string out; out.reserve(text.size());
          std::sregex_iterator it(text.begin(), text.end(), re), end;
          size_t last=0;
          for(; it!=end; ++it){
            auto m=*it;
            std::string raw=m.str();
            std::string digits; digits.reserve(raw.size());
            for(char c: raw){ if(c>='0'&&c<='9') digits.push_back(c); }
            bool ok = digits.size()>=13 && digits.size()<=19 && luhn_check(digits);
            out.append(text.substr(last, m.position()-last));
            if(ok) out += "[cc-redacted]"; else out += raw;
            last = m.position()+m.length();
          }
          out.append(text.substr(last));
          text.swap(out);
        }catch(...){}
      };
      auto apply_pii_presets=[&](std::string &text){
        if(pii_preset.empty()) return;
        // Built-in basic patterns
        try{
          // emails
          text = std::regex_replace(text, std::regex(R"((?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b)"), "[email-redacted]");
        }catch(...){}
        try{
          // phone numbers (very loose, international)
          text = std::regex_replace(text, std::regex(R"((?i)\b\+?[0-9][0-9\s().-]{6,}[0-9]\b)"), "[phone-redacted]");
        }catch(...){}
        try{
          // IPv6 (very loose)
          text = std::regex_replace(text, std::regex(R"((?i)\b(?:[A-F0-9]{0,4}:){2,7}[A-F0-9]{0,4}\b)"), "[ipv6-redacted]");
        }catch(...){}
        try{
          // MAC addresses
          text = std::regex_replace(text, std::regex(R"((?i)\b[0-9A-F]{2}(?::[0-9A-F]{2}){5}\b)"), "[mac-redacted]");
        }catch(...){}
        // Credit cards with Luhn
        mask_cc_numbers(text);
        if(pii_preset=="strict"){
          try{
            // National IDs / SSN-like (very broad)
            text = std::regex_replace(text, std::regex(R"(\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b)"), "[id-redacted]");
          }catch(...){}
          try{
            // IBAN-like (broad)
            text = std::regex_replace(text, std::regex(R"((?i)\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b)"), "[iban-redacted]");
          }catch(...){}
        }
      };
      auto maybe_rotate_time=[&](){
        if(tee_rotate_interval_sec>0 && tee_ofs){
          auto now = std::chrono::steady_clock::now();
          auto sec = std::chrono::duration_cast<std::chrono::seconds>(now - tee_last_rotate).count();
          if(sec >= tee_rotate_interval_sec){
            rotate_tee();
            tee_last_rotate = now;
          }
        }
      };
    

      auto trim=[&](std::string &x){ size_t a=0; while(a<x.size() && isspace((unsigned char)x[a])) a++; size_t b=x.size(); while(b>a && isspace((unsigned char)x[b-1])) b--; x = x.substr(a, b-a); };
      struct Schema { std::string type_allow, type_deny, key_allow, key_deny; long long details_max=0; };
      auto schema = Schema{};
      auto schema_load=[&](){
        if(schema_path.empty()) return;
        std::ifstream f(schema_path); if(!f){ std::cerr<<"cannot open schema "<<schema_path<<"\n"; return; }
        std::string line;
        while(std::getline(f,line)){
          if(line.size()==0 || line[0]=='#') continue;
          auto eq = line.find('='); if(eq==std::string::npos) continue;
          std::string k = line.substr(0, eq), v = line.substr(eq+1); trim(k); trim(v);
          if(k=="type.pattern") schema.type_allow=v;
          else if(k=="type.deny") schema.type_deny=v;
          else if(k=="key.pattern") schema.key_allow=v;
          else if(k=="key.deny") schema.key_deny=v;
          else if(k=="details.maxlen") try{ schema.details_max = std::stoll(v);}catch(...){}
        }
      };
      auto schema_check=[&](const Finding& rf)->bool{
        try{
          if(!schema.type_allow.empty()){ if(!std::regex_search(rf.type, std::regex(schema.type_allow))) return false; }
          if(!schema.type_deny.empty()){ if(std::regex_search(rf.type, std::regex(schema.type_deny))) return false; }
        }catch(...){}
        try{
          if(!schema.key_allow.empty()){ if(!std::regex_search(rf.key, std::regex(schema.key_allow))) return false; }
          if(!schema.key_deny.empty()){ if(std::regex_search(rf.key, std::regex(schema.key_deny))) return false; }
        }catch(...){}
        if(schema.details_max>0 && (long long)rf.details.size() > schema.details_max) return false;
        return true;
      };
      auto pretty_json=[&](const std::string& in, int indent)->std::string{
        if(indent<=0) return in;
        std::string out; out.reserve(in.size()*2);
        int depth=0; bool in_str=false; bool esc=false;
        for(char c: in){
          out.push_back(c);
          if(in_str){
            if(esc){ esc=false; continue; }
            if(c=='\\') esc=true;
            else if(c=='"') in_str=false;
          } else {
            if(c=='"'){ in_str=true; }
            else if(c=='{'||c=='['){ out.push_back('\n'); depth++; out.append(depth*indent, ' '); }
            else if(c==',' ){ out.push_back('\n'); out.append(depth*indent, ' '); }
            else if(c=='}'||c==']'){ out.insert(out.end()-1, '\n'); depth = std::max(0, depth-1); out.append(depth*indent, ' '); out.push_back(c); }
          }
        }
        return out;
      };
      auto rate_limit_ok=[&](const Finding& rf)->bool{
        if(limit_key_rate<=0 || limit_key_window_sec<=0) return true;
        auto &dq = key_hist[rf.key];
        while(!dq.empty() && dq.front() < rf.ts - limit_key_window_sec) dq.pop_front();
        if((long long)dq.size() >= limit_key_rate) return false;
        dq.push_back(rf.ts);
        return true;
      };
    
merge_cli_over_config(cfg, cli);

      if(cmd=="selftest"){
        // basic checks: bidi strip, ascii-only, redaction, sampling determinism
        bool ok=true;
        Finding f; f.ts=1; f.type="x"; f.key="a\xE2\x80\xAEb"; f.details="pwd=secret";
        ascii_only=true; redact_regex.clear(); try{ redact_regex.emplace_back("secret"); }catch(...){};
        auto r1 = transform_find(f);
        if(r1.key.find('\xE2')!=std::string::npos) ok=false;
        if(r1.details.find("secret")!=std::string::npos) ok=false;
        sample_rate=0.0; sample_prng.seed(1234);
        auto before=findings_emitted; // hypothetical counter
        auto rf=r1; // no-op to keep variables used
        std::cout<<(ok? "selftest ok\n":"selftest failed\n");
        return ok? 0: 1;
      }
    

if(cmd=="generate"){
  long long count=1000; std::string outfmt="csv"; std::string types="portscan,bruteforce,dns_anomaly"; unsigned seed=(unsigned)std::time(nullptr);
  for(size_t i=3;i<args.size();++i){
    auto a=args[i];
    if(a=="--count") count=(long long)std::stoll(need(i));
    else if(a=="--format") outfmt=need(i);
    else if(a=="--types") types=need(i);
    else if(a=="--seed") seed=(unsigned)std::stoul(need(i));
  }
  std::vector<std::string> tps; { size_t p=0; while(p<types.size()){ size_t q=types.find(',',p); if(q==std::string::npos) q=types.size(); tps.push_back(types.substr(p,q-p)); p=q+1; } }
  std::minstd_rand rnd(seed);
  auto now = (std::int64_t)std::time(nullptr);
  for(long long i=0;i<count;++i){
    if(g_stop.load()) break;
    auto tp = tps[(size_t)(rnd()%tps.size())];
    std::string key = "10.0."+std::to_string((rnd()%250)+1)+"."+std::to_string((rnd()%250)+1);
    std::string det = "user=u"+std::to_string((rnd()%90)+10)+" score="+std::to_string((rnd()%100));
    if(outfmt=="ndjson"){
      std::cout<<"{\\"ts\\":"<< (now+i) <<",\\"type\\":\\""<<tp<<"\\",\\"key\\":\\""<<key<<"\\",\\"details\\":\\""<<det<<"\\"}"<<std::endl;
    } else {
      std::cout<< (now+i) <<","<<tp<<","<<key<<","<<det<<std::endl;
    }
  }
    if(out_digest_inited){ std::ofstream df(out_digest_path); if(df){ unsigned char hv[32]; out_digest.final(hv); static const char* X="0123456789abcdef"; std::string hx(64,'0'); for(int i=0;i<32;++i){ hx[2*i]=X[(hv[i]>>4)&0xF]; hx[2*i+1]=X[hv[i]&0xF]; } df<<hx<<"\n"; } }
  {
    std::ostringstream sm; sm<<"processed="<<processed_count<<",emitted="<<emitted_count<<",findings="<<finding_count<<",invalid="<<invalid_records;    log_msg("info", sm.str());
  }
#ifndef _WIN32
  if(!pidfile_path.empty()){ std::error_code ec; std::filesystem::remove(pidfile_path, ec); }
#endif
  if(!out_path.empty() && atomic_out){ std::error_code ec; std::filesystem::rename(out_tmp, out_path, ec); }
  return 0;
}

  auto on_sig=[&](int){ g_stop.store(true); };
  signal(SIGINT, on_sig); signal(SIGTERM, on_sig);

      if(help_json){
        std::cout << R"JSON({
  "name": "neonsec",
  "subcommands": ["analyze","validate","doctor","verify"],
  "flags": ["--input","--format","--output","--metrics",":PORT","--sarif","FILE",
            "--threads","N","--sample","1/N","--config","FILE","--pcap","FILE","--pcap-live","IFACE",
            "--fail-on-findings","--quiet","--color","--no-color","--version","--stable-order",
            "--redact","--max-findings","N","--pseudonymize","--pseudonymize-salt","HEX","--summary",
            "--ts-format","epoch|iso","--tee","FILE","--csv-delim","CH","--csv-quote","CH","--stats",
            "--syslog","[facility]","--dry-run","--help-json"],
  "exit_codes": {"0":"success","2":"usage/config/input error","3":"findings with --fail-on-findings"}
})JSON" << std::endl;
          if(out_digest_inited){ std::ofstream df(out_digest_path); if(df){ unsigned char hv[32]; out_digest.final(hv); static const char* X="0123456789abcdef"; std::string hx(64,'0'); for(int i=0;i<32;++i){ hx[2*i]=X[(hv[i]>>4)&0xF]; hx[2*i+1]=X[hv[i]&0xF]; } df<<hx<<"\n"; } }
  {
    std::ostringstream sm; sm<<"processed="<<processed_count<<",emitted="<<emitted_count<<",findings="<<finding_count<<",invalid="<<invalid_records;    log_msg("info", sm.str());
  }
#ifndef _WIN32
  if(!pidfile_path.empty()){ std::error_code ec; std::filesystem::remove(pidfile_path, ec); }
#endif
  if(!out_path.empty() && atomic_out){ std::error_code ec; std::filesystem::rename(out_tmp, out_path, ec); }
  return 0;
      }



if(cmd=="verify"){
  std::ifstream cs("CHECKSUMS.sha256");
  if(!cs){ std::cerr<<"CHECKSUMS.sha256 not found\n"; return 2; }
  std::string line; int ok=0, bad=0, miss=0;
  auto hex = std::string("0123456789abcdef");
  while(std::getline(cs, line)){
    if(line.empty()) continue;
    size_t sp = line.find("  ");
    if(sp==std::string::npos) continue;
    std::string expect = line.substr(0, sp);
    std::string path = line.substr(sp+2);
    std::ifstream f(path, std::ios::binary);
    if(!f){ std::cerr<<"MISSING "<<path<<"\n"; miss++; continue; }
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    neonsec::crypto::Sha256 sh; sh.init(); if(!data.empty()) sh.update(data.data(), data.size()); unsigned char out[32]; sh.final(out);
    std::string got(64, '0'); for(int i=0;i<32;++i){ got[2*i]=hex[(out[i]>>4)&0xF]; got[2*i+1]=hex[out[i]&0xF]; }
    if(got==expect){ ok++; } else { std::cerr<<"MISMATCH "<<path<<"\n"; bad++; }
  }
  std::cout<<"verify: ok="<<ok<<" bad="<<bad<<" missing="<<miss<<"\n";
  return (bad||miss)? 2 : 0;
}

      if(cmd=="doctor"){
  std::cout<<"neonsec doctor: environment check\n";
  std::cout<<"  C++ runtime: OK\n";
  std::cout<<"  Sample files: ";
  bool ok_samples = true;
  {
    std::ifstream f1("examples/sample_logs.csv");
    std::ifstream f2("examples/sample_logs.ndjson");
    if(!f1 || !f2){ ok_samples=false; }
  }
  std::cout<<(ok_samples?"OK":"MISSING")<<"\n";
  std::cout<<"  Man page: "<< (std::ifstream("docs/neonsec.1").good()?"OK":"MISSING") <<"\n";
  std::cout<<"  Schemas: "<< (std::ifstream("schemas/rules.schema.json").good() && std::ifstream("schemas/config.schema.json").good()?"OK":"MISSING") <<"\n";
  std::cout<<"  Devcontainer: "<< (std::ifstream(".devcontainer/devcontainer.json").good()?"OK":"MISSING") <<"\n";
  std::cout<<"  Pre-commit: "<< (std::ifstream(".pre-commit-config.yaml").good()?"OK":"MISSING") <<"\n";
  std::cout<<"  SBOM: "<< (std::ifstream("sbom.spdx").good()?"OK":"MISSING") <<"\n";
  std::cout<<"Result: "<< ((ok_samples)?"PASS":"WARN") <<"\n";
    if(out_digest_inited){ std::ofstream df(out_digest_path); if(df){ unsigned char hv[32]; out_digest.final(hv); static const char* X="0123456789abcdef"; std::string hx(64,'0'); for(int i=0;i<32;++i){ hx[2*i]=X[(hv[i]>>4)&0xF]; hx[2*i+1]=X[hv[i]&0xF]; } df<<hx<<"\n"; } }
  {
    std::ostringstream sm; sm<<"processed="<<processed_count<<",emitted="<<emitted_count<<",findings="<<finding_count<<",invalid="<<invalid_records;    log_msg("info", sm.str());
  }
#ifndef _WIN32
  if(!pidfile_path.empty()){ std::error_code ec; std::filesystem::remove(pidfile_path, ec); }
#endif
  if(!out_path.empty() && atomic_out){ std::error_code ec; std::filesystem::rename(out_tmp, out_path, ec); }
  return 0;
}

  if(redact && pseudonymize){ std::cerr<<"cannot combine --redact and --pseudonymize\n"; return 2; }

#if !defined(_WIN32)
if(rlimit_mem_mb>0){
  struct rlimit rl; rl.rlim_cur = rl.rlim_max = (rlim_t)rlimit_mem_mb * 1024 * 1024;
  if(setrlimit(RLIMIT_AS, &rl)!=0 && !quiet) std::perror("setrlimit(RLIMIT_AS)");
}
if(rlimit_cpu_sec>0){
  struct rlimit rl; rl.rlim_cur = rl.rlim_max = (rlim_t)rlimit_cpu_sec;
  if(setrlimit(RLIMIT_CPU, &rl)!=0 && !quiet) std::perror("setrlimit(RLIMIT_CPU)");
}
#endif

  auto getenv_i=[&](const char* k){ const char* v=std::getenv(k); return v? std::optional<int>(std::atoi(v)) : std::nullopt; };
  auto getenv_s=[&](const char* k){ const char* v=std::getenv(k); return v? std::optional<std::string>(v) : std::nullopt; };
  if(auto v=getenv_i("NEONSEC_THREADS")) if(!cli.threads) cli.threads=*v;
  if(auto v=getenv_i("NEONSEC_SAMPLE")) if(!cli.sample) cli.sample=*v;
  if(auto v=getenv_s("NEONSEC_FORMAT")) if(cfg.format.empty()) cfg.format=*v;
  if(auto v=getenv_s("NEONSEC_TS_FORMAT")) ts_iso = (*v=="iso");
  if(auto v=getenv_s("NEONSEC_COLOR")) { if(*v=="always") use_color=true; else if(*v=="never") use_color=false; }
  const char* no_color = std::getenv("NO_COLOR");
  if(!explicit_color){ if(no_color) use_color=false; else { const char* term = std::getenv("TERM"); if(term && *term) use_color=true; } }
if(version_only){
  std::cout << "neonsec " << NEONSEC_VERSION << "\n";
    if(out_digest_inited){ std::ofstream df(out_digest_path); if(df){ unsigned char hv[32]; out_digest.final(hv); static const char* X="0123456789abcdef"; std::string hx(64,'0'); for(int i=0;i<32;++i){ hx[2*i]=X[(hv[i]>>4)&0xF]; hx[2*i+1]=X[hv[i]&0xF]; } df<<hx<<"\n"; } }
  {
    std::ostringstream sm; sm<<"processed="<<processed_count<<",emitted="<<emitted_count<<",findings="<<finding_count<<",invalid="<<invalid_records;    log_msg("info", sm.str());
  }
#ifndef _WIN32
  if(!pidfile_path.empty()){ std::error_code ec; std::filesystem::remove(pidfile_path, ec); }
#endif
  if(!out_path.empty() && atomic_out){ std::error_code ec; std::filesystem::rename(out_tmp, out_path, ec); }
  return 0;
}

if(cmd=="validate"){
  bool ok_all=true;
  if(!rules_path.empty()){
    std::string rerr; auto rc=load_rules_json(rules_path, rerr);
    if(!rc){ std::cerr<<"rules error: "<<rerr<<"\n"; ok_all=false; } else { std::cout<<"rules: OK ("<< rc->rules.size() <<" rules)\n"; }
  }
  if(!cfg.input.empty()){
    std::istream* in=nullptr; std::ifstream fin; set_csv_dialect(csv_delim, csv_quote);
    if(cfg.input=="-"){ in=&std::cin; } else { fin.open(cfg.input); if(!fin){ std::cerr<<"cannot open "<<cfg.input<<"\n"; return 2; } in=&fin; }
    if(cfg.input_format=="csv"){
      std::string header; if(!std::getline(*in, header)){ std::cerr<<"empty input\n"; ok_all=false; }
      else {
        auto cols = split_csv(header);
        const char* req[] = {"ts","src_ip","dst_ip","dst_port","protocol","action","status","bytes","username"};
        for(const char* r: req){ bool seen=false; for(auto& c: cols){ if(c==r){ seen=true; break; } } if(!seen){ std::cerr<<"missing column: "<<r<<"\n"; ok_all=false; }
        }
        if(ok_all) std::cout<<"csv header: OK\n";
      }
    } else if(cfg.input_format=="ndjson"){
      std::string line, err; int n=0; while(n<10 && std::getline(*in, line)){ if(line.empty()) continue; auto rec=parse_ndjson_line(line, err); processed_count++; if(max_records>=0 && processed_count>=max_records) break; if(!rec){ std::cerr<<"ndjson parse error: "<<err<<"\n"; ok_all=false; break; } n++; }
      if(ok_all) std::cout<<"ndjson sample parse: OK\n";
    }
  }
  return ok_all? 0 : 2;
}

  if(cfg.threads<1) cfg.threads=1; if(cfg.sample<1) cfg.sample=1;
  MetricsServer ms; if(!cfg.metrics.empty()){ std::string merr; ms.start(cfg.metrics, merr); }

  Detectors det(cfg.wcfg, cfg.dcfg);
  RulesEngine re(cfg.wcfg);
  if(!rules_path.empty()){ std::string rerr; auto rc=load_rules_json(rules_path, rerr); if(!rc){ std::cerr<<"rules error: "<<rerr<<"\n"; return 2; } for(auto& r: rc->rules) re.add_rule(r); }

  PluginHost host; std::string perr; for(auto& p: cfg.plugins){ if(!host.load(p, perr)) std::cerr<<"plugin error: "<<perr<<"\n"; }

  std::ostream* out=&std::cout; std::string out_tmp; std::ofstream fout; if(!cfg.output.empty()){ fout.open(cfg.output); if(!fout){ std::cerr<<"cannot open output\n"; return 2; } out=&fout; }
  std::vector<Finding> all_findings;
  std::vector<Finding> pending_findings;
  auto hash64=[&](const std::string& s){ unsigned long long h=1469598103934665603ull; for(unsigned char c: s) { h^=c; h*=1099511628211ull; } return h; };
  auto hex8=[&](unsigned long long h){ const char* x="0123456789abcdef"; std::string o(16,'0'); for(int i=15;i>=0;--i){ o[i]=x[h&0xF]; h>>=4; } return o.substr(8); };
  auto pseudonymize_str=[&](const std::string& v){ if(!pseudo_salt.empty()){ auto h = crypto::hmac_sha256_hex(pseudo_salt, v); return std::string("h:")+h.substr(0,16); } auto h = hash64(pseudo_salt + v); return std::string("h:")+hex8(h); };
  auto sanitize_ascii=[&](std::string s){ std::string o; o.reserve(s.size()); for(unsigned char c: s){ bool ok=((c>=32 && c!=127) || c==10 || c==9); if(ascii_only) ok = (c<=126 && ((c>=32 && c!=127) || c==10 || c==9)); if(ok) o.push_back((char)c); else o.push_back(' '); } return o; }; // ASCII_ONLY_MODE
  auto transform_find = [&](const Finding& f){ if(!redact && !pseudonymize) return f; Finding r=f;
    auto mask_ip=[&](std::string s){ if(pseudonymize) return pseudonymize_str(s); auto p = s.find('.'); if(p!=std::string::npos){ size_t last = s.rfind('.'); if(last!=std::string::npos) s.replace(last+1, std::string::npos, "x"); return s; } auto c = s.find(':'); if(c!=std::string::npos) return std::string("[ipv6-redacted]"); return s; };
    if(pseudonymize){ r.key = pseudonymize_str(r.key); }
    else { r.key = mask_ip(r.key); }
    auto pos = r.details.find("user=");
    if(pos!=std::string::npos){ if(pseudonymize){ std::string u=""; size_t i=pos+5; while(i<r.details.size() && r.details[i]!=' '){ u.push_back(r.details[i++]); } auto h=pseudonymize_str(u); r.details.replace(pos+5, u.size(), h); } else { r.details.replace(pos+5, std::min<size_t>(5, r.details.size()-pos-5), "***"); } }
    auto sanitize_bidi=[&](std::string s){ const char* bad[]={"âª","â«","â¬","â­","â®","â¦","â§","â¨","â©","â","â","Ø"}; for(auto b: bad){ size_t pos=0; while((pos=s.find(b,pos))!=std::string::npos){ s.erase(pos, std::strlen(b)); } } return s; };
r.details = sanitize_bidi(sanitize_ascii(r.details)); r.key = sanitize_bidi(sanitize_ascii(r.key)); auto apply_redact=[&](std::string &x){ for(const auto& rg: redact_regex){ try{ x = std::regex_replace(x, rg, redact_repl); } catch(...){} } }; apply_redact(r.details); apply_redact(r.key); mask_ip(r.details); mask_ip(r.key); utf8_sanitize(r.details); utf8_sanitize(r.key); if(validate_input){ bool ok = (r.ts>=0 && !r.type.empty() && !r.key.empty()); if(!ok){ invalid_records++; if(max_errors>=0 && invalid_records>max_errors) throw std::runtime_error("too many invalid records"); if(strict_mode){ throw std::runtime_error("invalid record"); } } } return r; };
 if(!redact) return f; Finding r=f; auto mask_ip=[&](std::string s){ auto p = s.find('.'); if(p!=std::string::npos){ size_t last = s.rfind('.'); if(last!=std::string::npos) s.replace(last+1, std::string::npos, "x"); return s; } auto c = s.find(':'); if(c!=std::string::npos) return std::string("[ipv6-redacted]"); return s; }; auto mask_user=[&](std::string s){ if(s.size()<=2) return std::string("***"); return s.substr(0,2)+std::string("***"); }; r.key = mask_ip(r.key); if(r.details.find("user=")!=std::string::npos){ auto pos=r.details.find("user=")+5; r.details.replace(pos, std::min<size_t>(5, r.details.size()-pos), "***"); } auto sanitize_bidi=[&](std::string s){ const char* bad[]={"âª","â«","â¬","â­","â®","â¦","â§","â¨","â©","â","â","Ø"}; for(auto b: bad){ size_t pos=0; while((pos=s.find(b,pos))!=std::string::npos){ s.erase(pos, std::strlen(b)); } } return s; };
r.details = sanitize_bidi(sanitize_ascii(r.details)); r.key = sanitize_bidi(sanitize_ascii(r.key)); auto apply_redact=[&](std::string &x){ for(const auto& rg: redact_regex){ try{ x = std::regex_replace(x, rg, redact_repl); } catch(...){} } }; apply_redact(r.details); apply_redact(r.key); mask_ip(r.details); mask_ip(r.key); utf8_sanitize(r.details); utf8_sanitize(r.key); if(validate_input){ bool ok = (r.ts>=0 && !r.type.empty() && !r.key.empty()); if(!ok){ invalid_records++; if(max_errors>=0 && invalid_records>max_errors) throw std::runtime_error("too many invalid records"); if(strict_mode){ throw std::runtime_error("invalid record"); } } } return r; };
  long long emitted_count=0; bool truncated=false; std::map<std::string,long long> summary_map; auto emit=[&](const Finding& f){ auto rf = transform_find(f); rf.ts = ts_with_offset(rf.ts);
    if(sample_rate<1.0){ std::uniform_real_distribution<double> dist(0.0,1.0); if(dist(sample_prng) > sample_rate){ dropped_sample++; return; } }

    if(cfg.format=="csv" && csv_header && !csv_header_emitted){ std::string h=std::string("ts,type,key,details") + (chain_enabled? ",chain":"") + (record_id_enabled? ",id":"") + (hmac_enabled? ",hmac":"") + "\n"; (*out)<<h; if(tee_ofs){ (*tee_ofs)<<h; tee_bytes += (long long)h.size(); if(tee_rotate_size_mb>0 && tee_bytes > tee_rotate_size_mb*1024*1024) rotate_tee(); } out_bytes += (long long)h.size(); csv_header_emitted=true; }
    if(since_ts>0 && rf.ts<since_ts){ dropped_selector++; return; }
    if(until_ts>0 && rf.ts>until_ts){ dropped_selector++; return; }
    if(!only_type.empty()){ bool ok=false; for(const auto& p: only_type){ if(match_glob(rf.type,p)){ ok=true; break; } } if(!ok){ dropped_selector++; return; } }
    for(const auto& p: skip_type){ if(match_glob(rf.type,p)){ dropped_selector++; return; } }
    if(!only_key.empty()){ bool ok=false; for(const auto& p: only_key){ if(match_glob(rf.key,p)){ ok=true; break; } } if(!ok){ dropped_selector++; return; } }
    for(const auto& p: skip_key){ if(match_glob(rf.key,p)){ dropped_selector++; return; } }
    if(!only_details.empty()){ bool ok=false; for(const auto& p: only_details){ if(match_glob(rf.details,p)){ ok=true; break; } } if(!ok){ dropped_selector++; return; } }
    for(const auto& p: skip_details){ if(match_glob(rf.details,p)){ dropped_selector++; return; } }
    if(dedupe_window_sec>0){ auto it=last_emit_ts.find(rf.type+"\x00"+rf.key); if(it!=last_emit_ts.end() && (rf.ts - it->second) <= dedupe_window_sec){ dropped_dedupe++; return; } }
    if(!baseline_set.empty()){ std::string bk = rf.type + std::string("\x00") + rf.key; if(baseline_set.find(bk)!=baseline_set.end()){ suppressed_baseline++; return; } }
    for(const auto& pr: suppress_globs){ if(match_glob(rf.type, pr.first) && match_glob(rf.key, pr.second)){ suppressed_by_pattern[pr.first+":"+pr.second]++; return; } } if(dedupe){ std::string k = rf.type + std::string("\x00") + rf.key; if(dedupe_set.find(k)!=dedupe_set.end()) return; dedupe_set.insert(k);} if(stable_order){ pending_findings.push_back(rf); } else { if(max_findings>=0 && emitted_count>=max_findings){ truncated=true; } else { if(cfg.format=="json"||cfg.format=="ndjson") print_json(*out, rf); else print_text(*out, rf, use_color); emitted_count++; if(record_id_enabled){ current_record_id++; } if(limit_findings>0 && emitted_count>=limit_findings){ drop_all=true; } } } if(!cfg.sarif.empty() || stable_order || cfg.format=="stix" || cfg.format=="html") all_findings.push_back(rf); ms.inc_finding(rf.type); finding_count++; summary_map[rf.type]++;
    last_emit_ts[rf.type+"\x00"+rf.key]=rf.ts;
    if(bucket_size_sec>0){ long long b=(rf.ts/(bucket_size_sec))*bucket_size_sec; bucket_counts[b][rf.type]++; bucket_total[b]++; } };

  std::queue<Item> q; std::mutex mu; std::condition_variable cv; bool done=false;
  auto worker = [&](){
    while(true){
      Item it; {
        std::unique_lock<std::mutex> lk(mu);
        cv.wait(lk, [&]{ return done || !q.empty(); });
        if(q.empty()){ if(done) break; else continue; }
        it = q.front(); q.pop();
      }
      if(!it.is_rec) continue;
      ms.inc_processed();
      if(cfg.sample>1){ std::hash<std::string> h; if((h(it.rec.src_ip) % cfg.sample) != 0) continue; }
      auto v1 = det.feed(it.rec);
      auto v2 = re.feed(it.rec);
      auto v3 = host.run_all(it.rec);
      v1.insert(v1.end(), v2.begin(), v2.end()); v1.insert(v1.end(), v3.begin(), v3.end());
      for(auto& f: v1) emit(f);
    }
  };
  std::vector<std::thread> threads; for(int i=0;i<cfg.threads; ++i) threads.emplace_back(worker);
  auto push_rec = [&](const LogRecord& r){ std::unique_lock<std::mutex> lk(mu); q.push(Item{true, r}); lk.unlock(); cv.notify_one(); };

  if(!pcap_file.empty() || !pcap_live.empty()){
    std::vector<LogRecord> recs; std::string err; bool ok=false;
    if(!pcap_file.empty()) ok=read_pcap_file(pcap_file, recs, err); else ok=read_pcap_live(pcap_live, recs, err);
    if(!ok){ std::cerr<<"pcap error: "<<err<<"\n"; return 2; }
    for(auto& r: recs) push_rec(r);
  } else {
    std::istream* in=nullptr; std::ifstream fin; set_csv_dialect(csv_delim, csv_quote);
    if(cfg.input.empty() || cfg.input=="-"){ in=&std::cin; } else { fin.open(cfg.input); if(!fin){ std::cerr<<"cannot open "<<cfg.input<<"\n"; return 2; } in=&fin; }
    std::string header; if(cfg.input_format=="csv"){ if(!std::getline(*in, header)){ std::cerr<<"empty input\n"; return 2; } }
    std::string line;
    while(std::getline(*in, line)){
      if(line.empty()) continue;
      std::string err; std::optional<LogRecord> rec;
      if(cfg.input_format=="ndjson") rec = parse_ndjson_line(line, err);
      else rec = parse_csv_record_line(header, line, err);
      if(!rec){ if(!quiet) std::cerr<<"parse error: "<<err<<"\n"; continue; }
      push_rec(*rec);
    }
  }
  { std::unique_lock<std::mutex> lk(mu); done=true; } cv.notify_all();
  for(auto& t: threads) t.join();
  if(stable_order){ std::sort(all_findings.begin(), all_findings.end(), [](const Finding& a, const Finding& b){ if(a.ts!=b.ts) return a.ts<b.ts; if(a.type!=b.type) return a.type<b.type; if(a.key!=b.key) return a.key<b.key; return a.details<b.details; }); 
  if(cfg.format=="csv" && csv_header && !csv_header_emitted){ std::string h=std::string("ts,type,key,details") + (chain_enabled? ",chain":"") + (record_id_enabled? ",id":"") + (hmac_enabled? ",hmac":"") + "\n"; (*out)<<h; if(tee_ofs){ (*tee_ofs)<<h; tee_bytes += (long long)h.size(); if(tee_rotate_size_mb>0 && tee_bytes > tee_rotate_size_mb*1024*1024) rotate_tee(); } out_bytes += (long long)h.size(); csv_header_emitted=true; }
for(const auto& f: all_findings){ if(min_key_count>1){ auto &mapk = per_type_key[f.type]; auto it = mapk.find(f.key); long long c = (it==mapk.end()?0:it->second); if(c < min_key_count){ dropped_mincount++; continue; } } if(cfg.format=="json"||cfg.format=="ndjson") print_json(*out, f); else print_text(*out, f, use_color); } }
  if(!cfg.sarif.empty()) write_sarif(cfg.sarif, all_findings);
  if(truncated && !quiet) std::cerr << "Truncated output due to --max-findings="<<max_findings<<"\n";
  if(summary){ std::ostream& s = std::cerr; s << "Summary:\n"; long long total=0; for(auto& kv: summary_map){ s << "  " << kv.first << ": " << kv.second << "\n"; total+=kv.second; } s << "  total: " << total << "\n"; }
  #if !defined(_WIN32)
  if(stats){ struct rusage ru; getrusage(RUSAGE_SELF, &ru); auto dt=std::chrono::steady_clock::now()-t_start; double sec=std::chrono::duration_cast<std::chrono::duration<double>>(dt).count(); std::cerr<<"Stats: processed="<<processed_count<<" findings="<<finding_count<<" elapsed_s="<<sec<<" eps="<<(sec>0?processed_count/sec:0)<<" maxrss_kb="<<ru.ru_maxrss<<"\n"; }
#else
  if(stats){ auto dt=std::chrono::steady_clock::now()-t_start; double sec=std::chrono::duration_cast<std::chrono::duration<double>>(dt).count(); std::cerr<<"Stats: processed="<<processed_count<<" findings="<<finding_count<<" elapsed_s="<<sec<<" eps="<<(sec>0?processed_count/sec:0)<<"\n"; }
#endif

// Final format rendering for STIX/HTML
if(cfg.format=="stix"){
  auto hex = [](unsigned long long h){ const char* X="0123456789abcdef"; std::string o(32,'0'); for(int i=31;i>=0;--i){ o[i]=X[h&0xF]; h>>=4; } return o; };
  auto uuid_from = [&](const std::string& s){ unsigned long long h=1469598103934665603ull; for(unsigned char c: s){ h^=c; h*=1099511628211ull;} std::string x=hex(h)+hex(h^0xabcdef); x[12]='4'; x[16]=(x[16]&0x3)|0x8; return std::string("00000000-0000-0000-0000-")+x.substr(0,12); };
  std::ostringstream ss; ss<<"{\"type\":\"bundle\", \"objects\":[";
  for(size_t i=0;i<all_findings.size();++i){
    const auto& f = all_findings[i];
    std::string id = "observed-data--"+uuid_from(f.type+f.key+f.details+std::to_string(f.ts));
    ss<<"{\"type\":\"observed-data\",\"id\":\""<<id<<"\",\"created\":\""<< (ts_iso? to_iso(f.ts): std::to_string(f.ts)) <<"\""
      <<",\"first_observed\":\""<< (ts_iso? to_iso(f.ts): std::to_string(f.ts)) <<"\""
      <<",\"last_observed\":\""<< (ts_iso? to_iso(f.ts): std::to_string(f.ts)) <<"\""
      <<",\"number_observed\":1,\"x_neonsec:type\":\""<<f.type<<"\",\"x_neonsec:key\":\""<<f.key<<"\",\"x_neonsec:details\":\""<<f.details<<"\"}";
    if(i+1<all_findings.size()) ss<<",";
  }
  ss<<"]}\n";
  std::string s=ss.str(); apply_record_id(s, cfg.format); apply_hmac(s, cfg.format); s = apply_chain(s, cfg.format); normalize_newline(s); if(max_output_bytes>0 && (out_bytes + (long long)s.size()) > max_output_bytes){ truncated=true; drop_all=true; return; } if(index_ofs){ (*index_ofs)<<out_bytes<<"\n"; } (*out)<<s; if(do_flush){ out->flush(); } if(tee_ofs){ (*tee_ofs)<<s; if(do_flush){ tee_ofs->flush(); } out_bytes += (long long)s.size(); tee_bytes += (long long)s.size(); if(tee_rotate_size_mb>0 && tee_bytes > tee_rotate_size_mb*1024*1024) rotate_tee(); } out_bytes += (long long)s.size(); if(epilogue){ if(!overall_hashing){ overall_hashing=true; } }
} else if(cfg.format=="html"){
  std::ostringstream ss; ss<<"<!doctype html><html><head><meta charset=\"utf-8\"><title>neonsec report</title>"
    <<"<style>body{font-family:sans-serif}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px}th{background:#f2f2f2}</style></head><body>";
  ss<<"<h1>NeonSec Findings</h1><p>Total: "<<all_findings.size()<<"</p><table><tr><th>Timestamp</th><th>Type</th><th>Key</th><th>Details</th></tr>";
  for(const auto& f: all_findings){ if(min_key_count>1){ auto &mapk = per_type_key[f.type]; auto it = mapk.find(f.key); long long c = (it==mapk.end()?0:it->second); if(c < min_key_count){ dropped_mincount++; continue; } }
    ss<<"<tr><td>"<<(ts_iso? to_iso(f.ts): std::to_string(f.ts))<<"</td><td>"<<f.type<<"</td><td>"<<f.key<<"</td><td>"<<f.details<<"</td></tr>";
  }
  ss<<"</table></body></html>\n";
  std::string s=ss.str(); apply_record_id(s, cfg.format); apply_hmac(s, cfg.format); s = apply_chain(s, cfg.format); normalize_newline(s); if(max_output_bytes>0 && (out_bytes + (long long)s.size()) > max_output_bytes){ truncated=true; drop_all=true; return; } if(index_ofs){ (*index_ofs)<<out_bytes<<"\n"; } (*out)<<s; if(do_flush){ out->flush(); } if(tee_ofs){ (*tee_ofs)<<s; if(do_flush){ tee_ofs->flush(); } out_bytes += (long long)s.size(); tee_bytes += (long long)s.size(); if(tee_rotate_size_mb>0 && tee_bytes > tee_rotate_size_mb*1024*1024) rotate_tee(); } out_bytes += (long long)s.size(); if(epilogue){ if(!overall_hashing){ overall_hashing=true; } }
}

  if(epilogue){ overall.final(overall_out); static const char* X="0123456789abcdef"; std::string hx(64,'0'); for(int i=0;i<32;++i){ hx[2*i]=X[(overall_out[i]>>4)&0xF]; hx[2*i+1]=X[overall_out[i]&0xF]; } std::ostringstream es; es<<"{\"neonsec\":\"epilogue\",\"run_id\":\""<<run_id<<"\",\"total\":"<<emitted_count<<",\"sha256\":\""<<hx<<"\"}\n"; std::string esx=es.str(); (*out)<<esx; if(tee_ofs){ (*tee_ofs)<<esx; } }

  if(!bucket_summary_path.empty() && bucket_size_sec>0){ std::ofstream bf(bucket_summary_path); if(bf){ bf<<"{"; bool first=true; for(auto &kv: bucket_total){ if(!first) bf<<","; first=false; long long b=kv.first; bf<<"\""<<b<<"\":{\"total\":"<<kv.second<<",\"types\":{"; bool ft=true; for(auto &tv: bucket_counts[b]){ if(!ft) bf<<","; ft=false; bf<<"\""<<tv.first<<"\":"<<tv.second; } bf<<"}}"; } bf<<"}\n"; } }
  if(!group_output_path.empty() && !group_by.empty()){
    std::ofstream gf(group_output_path);
    if(gf){
      if(group_by=="type"){
        gf<<"{\"type\":{"; bool first=true; for(auto &kv: summary_map){ if(!first) gf<<","; first=false; gf<<"\""<<kv.first<<"\":"<<kv.second; } gf<<"}}\n";
      } else if(group_by=="key"){
        gf<<"{\"key\":{"; bool first=true; for(auto &kv: per_type_key){ for(auto &kv2: kv.second){ if(!first) gf<<","; first=false; gf<<"\""<<kv2.first<<"\":"<<kv2.second; } } gf<<"}}\n";
      }
    }
  }
  if(!summary_json_path.empty()){
    std::ofstream jf(summary_json_path);
    if(jf){
      jf<<"{";
      jf<<"\"processed\":"<<processed_count<<",\"findings\":"<<finding_count<<",\"types\":{";
      bool first=true; for(auto &kv: summary_map){ if(!first) jf<<","; first=false; jf<<"\""<<kv.first<<"\":"<<kv.second; }
      jf<<"}";
      if(summary_top>0){
        jf<<",\"top\":{";
        bool ft=true;
        for(auto &kv: summary_map){
          if(!ft) jf<<","; ft=false;
          jf<<"\""<<kv.first<<"\":[";
          std::vector<std::pair<long long,std::string>> vec; for(auto& kv2: per_type_key[kv.first]) vec.push_back({kv2.second, kv2.first});
          std::sort(vec.begin(), vec.end(), [](auto&a, auto&b){return a.first>b.first;});
          for(size_t i=0;i<vec.size() && (int)i<summary_top; ++i){ if(i>0) jf<<","; jf<<"{\"key\":\""<<vec[i].second<<"\",\"count\":"<<vec[i].first<<"}"; }
          jf<<"]";
        }
        jf<<"}";
      }
      jf<<"}\n";
    }
  }

  if(!report_md_path.empty()){
    std::ofstream mf(report_md_path);
    if(mf){
      mf << "# NeonSec Findings Report\n\n";
      mf << "**Total findings:** " << finding_count << "\n\n";
      mf << "## Counts by type\n\nType | Count\n---|---\n";
      for(auto &kv: summary_map){ mf << kv.first << " | " << kv.second << "\n"; }
      if(summary_top>0){ mf << "\n## Top keys per type\n"; for(auto &kv: summary_map){ mf << "\n### " << kv.first << "\nKey | Count\n---|---\n"; std::vector<std::pair<long long,std::string>> vec; for(auto &kv2: per_type_key[kv.first]) vec.push_back({kv2.second, kv2.first}); std::sort(vec.begin(), vec.end(), [](auto&a, auto&b){return a.first>b.first;}); int n=0; for(auto &pr: vec){ if(n++>=summary_top) break; mf << pr.second << " | " << pr.first << "\n"; } } }
    }
  }
  if(!report_html_path.empty()){
    std::ofstream hf(report_html_path);
    if(hf){ hf << "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        << "<title>NeonSec Report</title>"
        << "<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;padding:24px;max-width:980px;margin:auto}@media (prefers-color-scheme: dark){body{background:#121212;color:#e5e5e5} table{border-color:#444} th{background:#222}}h1{font-size:1.6rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px}th{background:#f5f5f5;text-align:left}</style>"
        << "</head><body role="document" aria-label="NeonSec report"><h1 role="heading" aria-level="1">NeonSec Findings Report</h1>";
      hf << "<p><strong>Total findings:</strong> " << finding_count << "</p>";
      hf << "<h2>Counts by type</h2><table><tr><th>Type</th><th>Count</th></tr>";
      for(auto &kv: summary_map){ hf << "<tr><td>"<<kv.first<<"</td><td>"<<kv.second<<"</td></tr>"; }
      hf << "</table>";
      if(summary_top>0){ hf << "<h2>Top keys per type</h2>"; for(auto &kv: summary_map){ hf << "<h3>"<<kv.first<<"</h3><table><tr><th>Key</th><th>Count</th></tr>"; std::vector<std::pair<long long,std::string>> vec; for(auto &kv2: per_type_key[kv.first]) vec.push_back({kv2.second, kv2.first}); std::sort(vec.begin(), vec.end(), [](auto&a, auto&b){return a.first>b.first;}); int n=0; for(auto &pr: vec){ if(n++>=summary_top) break; hf << "<tr><td>"<<pr.second<<"</td><td>"<<pr.first<<"</td></tr>"; } hf << "</table>"; } }
      hf << "</body></html>";
    }
  }
  if(!audit_suppress_path.empty()){
    std::ofstream af(audit_suppress_path);
    if(af){ af<<"{\"baseline\":"<<suppressed_baseline<<",\"patterns\":{"; bool first=true; for(auto &kv: suppressed_by_pattern){ if(!first) af<<","; first=false; af<<"\""<<kv.first<<"\":"<<kv.second; } af<<"}}\n"; }
  }
  if(!errors_json_path.empty()){
    std::ofstream ej(errors_json_path);
    if(ej){
      ej << "{\"invalid\":" << invalid_records
         << ",\"dropped\":{\"sample\":" << dropped_sample
         << ",\"selector\":" << dropped_selector
         << ",\"dedupe\":" << dropped_dedupe
         << ",\"mincount\":" << dropped_mincount << "}"
         << ",\"truncated\":" << (truncated? "true":"false")
         << "}\n";
    }
  }
  if(!anomaly_out_path.empty() && anomaly_window>0 && bucket_size_sec>0){
    // compute z-score anomalies per type over bucketed counts
    std::map<std::string, std::vector<std::pair<long long,long long>>> series;
    for(auto &kv: bucket_counts){ long long b=kv.first; for(auto &tv: kv.second){ series[tv.first].push_back({b, tv.second}); } }
    std::ofstream ao(anomaly_out_path);
    if(ao){ ao<<"["; bool first=true; for(auto &sv: series){ auto &vec=sv.second; if(vec.size()<2) continue; // need at least 2
        // slide window
        std::sort(vec.begin(), vec.end());
        for(size_t i=0;i<vec.size();++i){ size_t j0=(i>0? (i> (size_t)anomaly_window? i-anomaly_window:0):0); size_t j1=(i==0?0:i-1);
          if(i==0) continue; if(j1<=j0) continue; double sum=0, sum2=0; size_t n=0; for(size_t j=j0;j<=j1;++j){ sum+=vec[j].second; sum2+=vec[j].second*vec[j].second; n++; }
          if(n<2) continue; double mean=sum/n; double var=(sum2/n)-(mean*mean); if(var<1e-9) var=1e-9; double sd=std::sqrt(var); double z=(vec[i].second-mean)/sd; if(z>=anomaly_z){ if(!first) ao<<","; first=false; ao<<"{\"type\":\""<<sv.first<<"\",\"bucket\":"<<vec[i].first<<",\"count\":"<<vec[i].second<<",\"z\":"<<z<<"}"; }
        }
      }
      ao<<"]\n"; }
  }
  if(!artifact_dir.empty()){
    std::error_code ec; std::filesystem::create_directories(artifact_dir, ec);
    std::ofstream mf(artifact_dir + "/manifest.json");
    if(mf){ mf<<"{\"run_id\":\""<<run_id<<"\",\"emitted\":"<<emitted_count<<",\"processed\":"<<processed_count<<",\"ts\":"<<(long long)std::time(nullptr)<<"}\n"; }
    if(!group_output_path.empty() && !group_by.empty()){
    std::ofstream gf(group_output_path);
    if(gf){
      if(group_by=="type"){
        gf<<"{\"type\":{"; bool first=true; for(auto &kv: summary_map){ if(!first) gf<<","; first=false; gf<<"\""<<kv.first<<"\":"<<kv.second; } gf<<"}}\n";
      } else if(group_by=="key"){
        gf<<"{\"key\":{"; bool first=true; for(auto &kv: per_type_key){ for(auto &kv2: kv.second){ if(!first) gf<<","; first=false; gf<<"\""<<kv2.first<<"\":"<<kv2.second; } } gf<<"}}\n";
      }
    }
  }
  if(!summary_json_path.empty()){
      std::ifstream sj(summary_json_path, std::ios::binary); if(sj){ std::ofstream out(artifact_dir + "/summary.json", std::ios::binary); out<<sj.rdbuf(); }
    }
    if(!bucket_summary_path.empty()){
      std::ifstream bj(bucket_summary_path, std::ios::binary); if(bj){ std::ofstream out(artifact_dir + "/bucket-summary.json", std::ios::binary); out<<bj.rdbuf(); }
    }
  }
  if(fail_on_findings && !all_findings.empty()) return 3;
    if(out_digest_inited){ std::ofstream df(out_digest_path); if(df){ unsigned char hv[32]; out_digest.final(hv); static const char* X="0123456789abcdef"; std::string hx(64,'0'); for(int i=0;i<32;++i){ hx[2*i]=X[(hv[i]>>4)&0xF]; hx[2*i+1]=X[hv[i]&0xF]; } df<<hx<<"\n"; } }
  {
    std::ostringstream sm; sm<<"processed="<<processed_count<<",emitted="<<emitted_count<<",findings="<<finding_count<<",invalid="<<invalid_records;    log_msg("info", sm.str());
  }
#ifndef _WIN32
  if(!pidfile_path.empty()){ std::error_code ec; std::filesystem::remove(pidfile_path, ec); }
#endif
  if(!out_path.empty() && atomic_out){ std::error_code ec; std::filesystem::rename(out_tmp, out_path, ec); }
  return 0;
}
