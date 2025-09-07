// SPDX-License-Identifier: Apache-2.0

#include "neonsec/metrics_server.hpp"
#include <cstring>
#include <string>
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

#ifdef NEONSEC_WITH_TLS
  #include <openssl/ssl.h>
  #include <openssl/err.h>
#endif

namespace neonsec {

static void close_sock(int s){
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

bool MetricsServer::start(const std::string& bind_addr, int port, const std::string& tls_cert, const std::string& tls_key){
    if (running_.load()) return true;
    running_.store(true);
    th_ = std::thread([this, bind_addr, port, tls_cert, tls_key]{
#ifdef _WIN32
        WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
        int srv = ::socket(AF_INET, SOCK_STREAM, 0);
        if (srv < 0) { running_.store(false); return; }
        sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons((uint16_t)port);
#ifdef _WIN32
        inet_pton(AF_INET, bind_addr.c_str(), &addr.sin_addr);
#else
        ::inet_pton(AF_INET, bind_addr.c_str(), &addr.sin_addr);
#endif
        int opt = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        if (bind(srv, (sockaddr*)&addr, sizeof(addr)) < 0) { close_sock(srv); running_.store(false); return; }
        listen(srv, 8);

#ifdef NEONSEC_WITH_TLS
        SSL_CTX* ctx = nullptr;
        if (!tls_cert.empty() && !tls_key.empty()){
            SSL_library_init();
            OpenSSL_add_all_algorithms();
            SSL_load_error_strings();
            ctx = SSL_CTX_new(TLS_server_method());
            if (!ctx){ running_.store(false); close_sock(srv); return; }
            if (SSL_CTX_use_certificate_file(ctx, tls_cert.c_str(), SSL_FILETYPE_PEM) <= 0 ||
                SSL_CTX_use_PrivateKey_file(ctx, tls_key.c_str(), SSL_FILETYPE_PEM) <= 0){
                SSL_CTX_free(ctx); close_sock(srv); running_.store(false); return;
            }
        }
#endif

        const char* body_header = "HTTP/1.0 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n\r\n";
        while (running_.load()){
            sockaddr_in cli{}; socklen_t cl = sizeof(cli);
            int c = accept(srv, (sockaddr*)&cli, &cl);
            if (c < 0) continue;
            std::string body;
            body += "# HELP neonsec_lines_total Total lines processed\n# TYPE neonsec_lines_total counter\n";
            body += "neonsec_lines_total " + std::to_string(m_.lines.load()) + "\n";
            body += "# HELP neonsec_findings_total Total findings\n# TYPE neonsec_findings_total counter\n";
            body += "neonsec_findings_total " + std::to_string(m_.findings.load()) + "\n";
            body += "neonsec_portscan_total " + std::to_string(m_.portscan.load()) + "\n";
            body += "neonsec_ddos_total " + std::to_string(m_.ddos.load()) + "\n";
            body += "neonsec_bruteforce_total " + std::to_string(m_.bruteforce.load()) + "\n";
            std::string resp = std::string(body_header) + body;

#ifdef NEONSEC_WITH_TLS
            if (ctx){
                SSL* ssl = SSL_new(ctx);
                SSL_set_fd(ssl, c);
                if (SSL_accept(ssl) > 0){
                    SSL_write(ssl, resp.c_str(), (int)resp.size());
                }
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close_sock(c);
                continue;
            }
#endif
#ifdef _WIN32
            send(c, resp.c_str(), (int)resp.size(), 0);
#else
            ::send(c, resp.c_str(), (int)resp.size(), 0);
#endif
            close_sock(c);
        }
#ifdef NEONSEC_WITH_TLS
        // free ctx if allocated
        // (ctx may be null if certs were not supplied)
        extern void SSL_CTX_free(SSL_CTX*);
        // NOLINTNEXTLINE
        if (false) SSL_CTX_free(nullptr); // keep symbol reference happy for some linkers
#endif
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
