// SPDX-License-Identifier: Apache-2.0

#include "neonsec/metrics_server.hpp"
#include <cstring>
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
#endif

namespace neonsec {

static void close_sock(int s){
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

bool MetricsServer::start(const std::string& bind_addr, int port){
    if (running_.load()) return true;
    running_.store(true);
    th_ = std::thread([this, bind_addr, port]{
#ifdef _WIN32
        WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
        int srv = ::socket(AF_INET, SOCK_STREAM, 0);
        if (srv < 0) { running_.store(false); return; }
        sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons((uint16_t)port);
        if (bind_addr == "0.0.0.0") {
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
#ifdef _WIN32
            inet_pton(AF_INET, bind_addr.c_str(), &addr.sin_addr);
#else
            ::inet_pton(AF_INET, bind_addr.c_str(), &addr.sin_addr);
#endif
        }
        int opt = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        if (bind(srv, (sockaddr*)&addr, sizeof(addr)) < 0) { close_sock(srv); running_.store(false); return; }
        listen(srv, 8);
        while (running_.load()){
            sockaddr_in cli{}; socklen_t cl = sizeof(cli);
            int c = accept(srv, (sockaddr*)&cli, &cl);
            if (c < 0) continue;
            const char* body_header = "HTTP/1.0 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n\r\n";
            std::string body;
            body += "# HELP neonsec_lines_total Total lines processed\n# TYPE neonsec_lines_total counter\n";
            body += "neonsec_lines_total " + std::to_string(m_.lines.load()) + "\n";
            body += "# HELP neonsec_findings_total Total findings\n# TYPE neonsec_findings_total counter\n";
            body += "neonsec_findings_total " + std::to_string(m_.findings.load()) + "\n";
            body += "neonsec_portscan_total " + std::to_string(m_.portscan.load()) + "\n";
            body += "neonsec_ddos_total " + std::to_string(m_.ddos.load()) + "\n";
            std::string resp = std::string(body_header) + body;
#ifdef _WIN32
            send(c, resp.c_str(), (int)resp.size(), 0);
#else
            ::send(c, resp.c_str(), (int)resp.size(), 0);
#endif
            close_sock(c);
        }
        close_sock(srv);
#ifdef _WIN32
        WSACleanup();
#endif
    });
    return true;
}

void MetricsServer::stop(){
    if (!running_.load()) return;
    running_.store(false);
    if (th_.joinable()) th_.join();
}

} // namespace neonsec
