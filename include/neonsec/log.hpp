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
        : dir_(std::move(dir)), prefix_(std::move(prefix)) {}

    void set_level(LogLevel lvl){ lvl_.store(static_cast<int>(lvl)); }

    void log(LogLevel lvl, const std::string& msg){
        if (static_cast<int>(lvl) < lvl_.load()) return;
        std::lock_guard<std::mutex> lk(mu_);
        rotate_if_needed();
        auto ts = current_ts();
        std::string line = ts + " [" + level_name(lvl) + "] " + msg + "\n";
        std::cout << line;
        if (out_.is_open()) out_ << line;
    }

private:
    static std::string level_name(LogLevel l){
        switch(l){
            case LogLevel::TRACE: return "TRACE";
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO:  return "INFO";
            case LogLevel::WARN:  return "WARN";
            case LogLevel::ERROR: return "ERROR";
        }
        return "INFO";
    }
    static std::string current_ts(){
        std::time_t t = std::time(nullptr);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
        return buf;
    }
    std::string current_date(){
        std::time_t t = std::time(nullptr);
        std::tm tm = *std::localtime(&t);
        char buf[16]; std::strftime(buf,sizeof(buf),"%Y%m%d",&tm);
        return buf;
    }
    void open_file(){
        std::filesystem::create_directories(dir_);
        auto path = dir_ / (prefix_ + "-" + current_date() + ".log");
        out_.open(path, std::ios::app);
    }
    void rotate_if_needed(){
        if (!out_.is_open()) open_file();
    }

    std::filesystem::path dir_;
    std::string prefix_;
    std::mutex mu_;
    std::ofstream out_;
    std::atomic<int> lvl_{static_cast<int>(LogLevel::INFO)};
};

} // namespace neonsec
