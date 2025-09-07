// SPDX-License-Identifier: Apache-2.0
#include "neonsec/pcap_input.hpp"
#ifdef NEONSEC_WITH_PCAP
#include <pcap/pcap.h>
#include <ctime>
namespace neonsec {
static std::int64_t now_epoch(){ return (std::int64_t)time(nullptr); }
bool read_pcap_file(const std::string& path, std::vector<LogRecord>& out, std::string& err){
  char ebuf[PCAP_ERRBUF_SIZE]; pcap_t* p = pcap_open_offline(path.c_str(), ebuf);
  if(!p){ err=ebuf; return false; }
  struct pcap_pkthdr* hdr; const u_char* pkt;
  while(pcap_next_ex(p, &hdr, &pkt)>0){ LogRecord r{}; r.ts = hdr->ts.tv_sec? hdr->ts.tv_sec : now_epoch(); r.src_ip="pcap"; r.dst_ip="pcap"; r.dst_port=0; r.protocol="pcap"; r.action="transfer"; r.status="ok"; r.bytes=hdr->caplen; out.push_back(r); }
  pcap_close(p); return true;
}
bool read_pcap_live(const std::string& iface, std::vector<LogRecord>& out, std::string& err){
  char ebuf[PCAP_ERRBUF_SIZE]; pcap_t* p = pcap_open_live(iface.c_str(), 65535, 1, 1000, ebuf);
  if(!p){ err=ebuf; return false; }
  struct pcap_pkthdr* hdr; const u_char* pkt;
  for(int i=0;i<1000 && pcap_next_ex(p, &hdr, &pkt)>=0; ++i){ LogRecord r{}; r.ts = hdr->ts.tv_sec? hdr->ts.tv_sec : now_epoch(); r.src_ip="pcap"; r.dst_ip="pcap"; r.dst_port=0; r.protocol="pcap"; r.action="transfer"; r.status="ok"; r.bytes=hdr->caplen; out.push_back(r); }
  pcap_close(p); return true;
}
} // namespace neonsec
#endif
