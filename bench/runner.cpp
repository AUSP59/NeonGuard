#include <chrono>
#include <iostream>
#include <string>

int main() {
    using clock = std::chrono::steady_clock;
    auto start = clock::now();

    std::size_t lines = 0;
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);
    std::string s;
    while (std::getline(std::cin, s)) {
        ++lines;
    }

    auto end = clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "Processed lines: " << lines << "\\n";
    std::cout << "Elapsed (ms): " << ms << "\\n";
    if (ms > 0) {
        double throughput = (lines * 1000.0) / ms;
        std::cout << "Throughput (lines/sec): " << throughput << "\\n";
    }
    return 0;
}