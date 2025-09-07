// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <ctime>

namespace neonsec {

enum class LogLevel { TRACE=0, DEBUG, INFO, WARN, ERROR };

class Logger {
public:
    explicit Logger(std::filesystem::path dir = "logs", std::string prefix = "neonsec")
        : dir_(std::move(dir)), prefix_(std::move(prefix)) {
        std::filesystem::create_directories(dir_);
        open_file();
    }

    void set_level(LogLevel lvl){ lvl_.store(static_cast<int>(lvl)); }
    LogLevel level() const { return static_cast<LogLevel>(lvl_.load()); }

    void log(LogLevel lvl, const std::string& msg){
        if (static_cast<int>(lvl) < lvl_.load()) return;
        std::lock_guard<std::mutex> lk(mu_);
        rotate_if_needed();
        std::string line = timestamp() + " [" + name(lvl) + "] " + msg + "\n";
        if (out_.is_open()) { out_ << line << std::flush; }
        std::cout << line;
    }

    static const char* name(LogLevel l){
        switch(l){
            case LogLevel::TRACE: return "TRACE";
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO:  return "INFO";
            case LogLevel::WARN:  return "WARN";
            case LogLevel::ERROR: return "ERROR";
            default: return "INFO";
        }
    }

private:
    static std::string timestamp(){
        std::time_t t = std::time(nullptr);
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        char buf[32]; std::strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",&tm);
        return buf;
    }
    void open_file(){
        auto p = dir_ / (prefix_ + "-" + today() + ".log");
        out_.open(p, std::ios::app);
    }
    static std::string today(){
        std::time_t t = std::time(nullptr);
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        char buf[16]; std::strftime(buf,sizeof(buf),"%Y%m%d",&tm);
        return buf;
    }
    void rotate_if_needed(){
        if (!out_.is_open()) open_file();
        // rotate per day (file name encodes day)
    }

    std::filesystem::path dir_;
    std::string prefix_;
    std::mutex mu_;
    std::ofstream out_;
    std::atomic<int> lvl_{static_cast<int>(LogLevel::INFO)};
};

} // namespace neonsec
