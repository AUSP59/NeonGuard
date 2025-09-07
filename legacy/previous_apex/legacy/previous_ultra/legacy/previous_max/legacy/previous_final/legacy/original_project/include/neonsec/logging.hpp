// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <iostream>
#include <string>
#include <cstdlib>
namespace neonsec {
enum class LogLevel { ERROR=0, WARN=1, INFO=2, DEBUG=3 };
inline LogLevel current_level(){
  const char* v = std::getenv("NEONSEC_LOG");
  if(!v) return LogLevel::INFO;
  std::string s(v);
  if(s=="debug") return LogLevel::DEBUG;
  if(s=="info") return LogLevel::INFO;
  if(s=="warn") return LogLevel::WARN;
  return LogLevel::ERROR;
}
inline void log(LogLevel lvl, const std::string& msg){
  if((int)lvl <= (int)current_level()){
    const char* name = (lvl==LogLevel::ERROR?"ERROR": lvl==LogLevel::WARN?"WARN": lvl==LogLevel::INFO?"INFO":"DEBUG");
    std::cerr << "[neonsec][" << name << "] " << msg << "\n";
  }
}
} // namespace neonsec
