// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <atomic>
#include <thread>
#include <string>

namespace neonsec {

struct Metrics {
    std::atomic<long long> lines{0};
    std::atomic<long long> findings{0};
    std::atomic<long long> portscan{0};
    std::atomic<long long> ddos{0};
};

class MetricsServer {
public:
    MetricsServer() = default;
    ~MetricsServer(){ stop(); }

    bool start(const std::string& bind_addr = "0.0.0.0", int port = 9100);
    void stop();

    Metrics& metrics(){ return m_; }

private:
    Metrics m_;
    std::thread th_;
    std::atomic<bool> running_{false};
};

} // namespace neonsec
