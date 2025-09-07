// SPDX-License-Identifier: Apache-2.0

#include "neonsec/log.hpp"
#include "neonsec/csv_reader.hpp"
#include "neonsec/ndjson_reader.hpp"
#include "neonsec/window.hpp"
#include "neonsec/detectors.hpp"
#include "neonsec/rules.hpp"
#include "neonsec/reporters.hpp"
#include "neonsec/metrics_server.hpp"
#include "neonsec/plugin_loader.hpp"
#include "neonsec/bounded_queue.hpp"
#include <iostream>
#include <filesystem>
#include <thread>
#include <atomic>

using namespace neonsec;

static void help(const char* exe){
    std::cout << "neonsec " << "3.0.0" << "\\n"
              << "Usage:\\n"
              << "  " << exe << " analyze --input <file|-> --format csv|ndjson [--window SEC] [--rules rules.json]\\n"
              << "         [--metrics <host:port>] [--plugin <path>]... [--threads N] [--outfmt text|json]\\n"
              << "Examples:\\n"
              << "  " << exe << " analyze --input examples/sample.csv --format csv --window 60 --metrics 0.0.0.0:9100 --outfmt json\\n";
}

int main(int argc, char** argv){
    if (argc < 2){ help(argv[0]); return 1; }
    std::string cmd = argv[1];
    if (cmd == "-h" || cmd == "--help"){ help(argv[0]); return 0; }
    if (cmd != "analyze"){ std::cerr << "Unknown command: " << cmd << "\\n"; help(argv[0]); return 1; }

    std::string input; std::string fmt; long long window = 60; std::string rules;
    int threads = std::max(2, (int)std::thread::hardware_concurrency());
    std::string metrics_host; int metrics_port = 0;
    std::vector<std::string> plugin_paths;
    std::string outfmt = "text";
    for (int i=2;i<argc;i++){
        std::string a = argv[i];
        if (a=="--input" && i+1<argc) input = argv[++i];
        else if (a=="--format" && i+1<argc) fmt = argv[++i];
        else if (a=="--window" && i+1<argc) window = std::stoll(argv[++i]);
        else if (a=="--rules" && i+1<argc) rules = argv[++i];
        else if (a=="--metrics" && i+1<argc) {{ 
            std::string v = argv[++i]; 
            auto pos = v.rfind(':');
            if (pos != std::string::npos) {{ metrics_host = v.substr(0,pos); metrics_port = std::stoi(v.substr(pos+1)); }}
        }}
        else if (a=="--threads" && i+1<argc) threads = std::stoi(argv[++i]);
        else if (a=="--plugin" && i+1<argc) plugin_paths.push_back(argv[++i]);
        else if (a=="--outfmt" && i+1<argc) outfmt = argv[++i];
        else if (a=="-h" || a=="--help"){ help(argv[0]); return 0; }
        else{ std::cerr << "Unknown arg: " << a << "\\n"; return 1; }
    }
    if (input.empty() || (fmt!="csv" && fmt!="ndjson")){ std::cerr << "--input and --format required\\n"; return 1; }
    if (outfmt!="text" && outfmt!="json"){ std::cerr << "--outfmt must be text or json\\n"; return 1; }

    Logger log;
    Thresholds th{};
    if (!rules.empty()){
        std::string err;
        auto t = load_thresholds_json(rules, err);
        if (!t){ std::cerr << "Invalid rules: " << err << "\\n"; return 2; }
        th = *t;
    }

    MetricsServer ms; if (metrics_port>0) ms.start(metrics_host.empty() ? "0.0.0.0" : metrics_host, metrics_port);

    SlidingWindow win(window);
    std::istream* in = nullptr;
    std::ifstream f;
    if (input == "-"){ in = &std::cin; }
    else { f.open(input); if (!f){ std::cerr << "Cannot open input\\n"; return 1; } in = &f; }

    std::vector<LoadedPlugin> plugins;
    for (auto& pth: plugin_paths){
        LoadedPlugin lp{};
        if (load_plugin(pth, lp)) { plugins.push_back(lp); log.log(LogLevel::INFO, "Loaded plugin: " + pth); }
        else { log.log(LogLevel::WARN, "Failed to load plugin: " + pth); }
    }

    BoundedQueue<std::string> q(10000);
    std::atomic<bool> done=false;
    std::thread reader([&]{
        std::string line;
        bool first=true;
        while (std::getline(*in, line)){
            if (fmt=="csv" && first){
                bool header = true;
                for (char c: line){ if (std::isdigit((unsigned char)c) || c==',' || c=='-') { header=false; break; } }
                if (!header) { q.push(line); }
                first=false; continue;
            }
            q.push(line);
        }
        done.store(true);
        q.close();
    });

    auto worker = [&](int id){
        std::string err;
        while (true){
            auto item = q.pop();
            if (!item.has_value()){ if (done.load()) break; else continue; }
            ms.metrics().lines.fetch_add(1);
            auto line = std::move(*item);
            auto rec = (fmt=="csv") ? parse_csv_line(line, err) : parse_ndjson_line(line, err);
            if (!rec) continue;
            win.add(*rec);
            std::vector<Finding> out;
            detect_portscan(win, *rec, th, out);
            detect_ddos(win, *rec, th, out);
            for (auto& lp: plugins) if (lp.hook) lp.hook(*rec, win, out);
            for (auto& fnd: out){
                ms.metrics().findings.fetch_add(1);
                if (fnd.type=="portscan") ms.metrics().portscan.fetch_add(1);
                if (fnd.type=="ddos") ms.metrics().ddos.fetch_add(1);
                if (outfmt=="json") report_json(fnd); else report_text(fnd);
            }
        }
    };

    std::vector<std::thread> pool;
    for (int i=0;i<threads;i++) pool.emplace_back(worker, i);
    reader.join();
    for (auto& t: pool) t.join();
    for (auto& p: plugins) unload_plugin(p);
    ms.stop();
    log.log(LogLevel::INFO, "Analysis complete.");
    return 0;
}
