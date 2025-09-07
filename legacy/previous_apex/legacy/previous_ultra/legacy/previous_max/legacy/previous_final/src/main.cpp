
#include "neonsec/log.hpp"
#include "neonsec/csv_reader.hpp"
#include "neonsec/window.hpp"
#include "neonsec/detectors.hpp"
#include "neonsec/rules.hpp"
#include "neonsec/reporters.hpp"
#include <iostream>
#include <filesystem>

using namespace neonsec;

static void help(const char* exe){
    std::cout << "neonsec " << "1.0.0" << "\n"
              << "Usage:\n"
              << "  " << exe << " analyze --input <file|-> [--window SEC] [--rules rules.json]\n"
              << "Examples:\n"
              << "  " << exe << " analyze --input examples/sample.csv --window 60\n";
}

int main(int argc, char** argv){
    if (argc < 2){ help(argv[0]); return 1; }
    std::string cmd = argv[1];
    if (cmd == "-h" || cmd == "--help"){ help(argv[0]); return 0; }
    if (cmd != "analyze"){ std::cerr << "Unknown command: " << cmd << "\n"; help(argv[0]); return 1; }

    std::string input; long long window = 60; std::string rules;
    for (int i=2;i<argc;i++){
        std::string a = argv[i];
        if (a=="--input" && i+1<argc) input = argv[++i];
        else if (a=="--window" && i+1<argc) window = std::stoll(argv[++i]);
        else if (a=="--rules" && i+1<argc) rules = argv[++i];
        else if (a=="-h" || a=="--help"){ help(argv[0]); return 0; }
        else{ std::cerr << "Unknown arg: " << a << "\n"; return 1; }
    }
    if (input.empty()){ std::cerr << "--input required\n"; return 1; }

    Logger log;
    Thresholds th{};
    if (!rules.empty()){
        std::string err;
        auto t = load_thresholds_json(rules, err);
        if (!t){ std::cerr << "Invalid rules: " << err << "\n"; return 2; }
        th = *t;
    }

    SlidingWindow win(window);
    std::istream* in = nullptr;
    std::ifstream f;
    if (input == "-"){ in = &std::cin; }
    else { f.open(input); if (!f){ std::cerr << "Cannot open input\n"; return 1; } in = &f; }

    std::string line;
    // Assume first line is header; skip if it contains non-digit
    if (std::getline(*in, line)){
        bool header = true;
        for (char c: line){ if (std::isdigit(static_cast<unsigned char>(c)) || c==',' || c=='-' ) { header=false; break; } }
        if (!header){
            // first line was data
            std::string err; auto rec = parse_csv_line(line, err);
            if (rec){
                win.add(*rec);
                std::vector<Finding> out;
                detect_portscan(win, *rec, th, out);
                detect_ddos(win, *rec, th, out);
                for (auto& f: out) report_text(f);
            }
        }
    }
    while (std::getline(*in, line)){
        std::string err;
        auto rec = parse_csv_line(line, err);
        if (!rec) continue;
        win.add(*rec);
        std::vector<Finding> out;
        detect_portscan(win, *rec, th, out);
        detect_ddos(win, *rec, th, out);
        for (auto& f: out) report_text(f);
    }
    log.log(LogLevel::INFO, "Analysis complete.");
    return 0;
}
