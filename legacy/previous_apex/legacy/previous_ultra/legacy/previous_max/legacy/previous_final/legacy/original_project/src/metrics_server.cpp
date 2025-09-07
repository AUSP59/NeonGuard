// SPDX-License-Identifier: Apache-2.0
#include "neonsec/metrics_server.hpp"
#include <string>
#include <vector>
#include <cstring>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
namespace neonsec {
MetricsServer::~MetricsServer(){ stop(); }
void MetricsServer::inc_processed(){ processed_.fetch_add(1, std::memory_order_relaxed); }
void MetricsServer::inc_finding(const std::string& t){ std::lock_guard<std::mutex> lk(mu_); finding_[t]++; }
static bool parse_hostport(const std::string& hp, std::string& host, int& port){
  if(hp.empty()) return false; auto pos = hp.rfind(':'); if(pos==std::string::npos){ host="127.0.0.1"; port=9464; return true; }
  host = hp.substr(0,pos); std::string p = hp.substr(pos+1); if(host.empty()) host="127.0.0.1"; port = p.empty()?9464:std::stoi(p); return true;
}
bool MetricsServer::start(const std::string& hostport, std::string& err){
  if(running_) return true; std::string host; int port=0; if(!parse_hostport(hostport, host, port)){ err="invalid host:port"; return false; }
  running_=true; th_ = std::thread([this, host, port]{ run(host, port); }); return true;
}
void MetricsServer::stop(){ if(running_){ running_=false;
#if !defined(_WIN32)
  if(sock_!=-1) ::shutdown(sock_, SHUT_RDWR);
#endif
  if(th_.joinable()) th_.join(); } }
void MetricsServer::run(const std::string& host, int port){
#if defined(_WIN32)
  WSADATA wsaData; WSAStartup(MAKEWORD(2,2), &wsaData);
#endif
  int sfd = ::socket(AF_INET, SOCK_STREAM, 0); if(sfd<0){ running_=false; return; } sock_ = sfd;
  int opt=1;
#if defined(_WIN32)
  setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
  setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
  sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons((uint16_t)port); addr.sin_addr.s_addr = inet_addr(host.c_str());
  if(::bind(sfd, (sockaddr*)&addr, sizeof(addr))<0){ running_=false; return; }
  ::listen(sfd, 8);
  while(running_){
#if defined(_WIN32)
    SOCKET c = ::accept(sfd, NULL, NULL); if(c==INVALID_SOCKET) break;
#else
    int c = ::accept(sfd, NULL, NULL); if(c<0) break;
#endif
    std::string body;
    body += "# HELP neonsec_processed_total Total processed records\n# TYPE neonsec_processed_total counter\n";
    body += "neonsec_processed_total "; body += std::to_string(processed_.load()); body += "\n";
    { std::lock_guard<std::mutex> lk(mu_); for(auto& kv: finding_){ body += "neonsec_findings_total{type=\""+kv.first+"\"} " + std::to_string(kv.second) + "\n"; } }
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
#if defined(_WIN32)
    send(c, resp.c_str(), (int)resp.size(), 0); closesocket(c);
#else
    ::send(c, resp.c_str(), resp.size(), 0); ::close(c);
#endif
  }
#if defined(_WIN32)
  closesocket(sfd); WSACleanup();
#else
  ::close(sfd);
#endif
}
} // namespace neonsec
