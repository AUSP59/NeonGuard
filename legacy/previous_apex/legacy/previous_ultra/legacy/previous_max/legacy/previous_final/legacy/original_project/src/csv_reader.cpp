// SPDX-License-Identifier: Apache-2.0
#include "neonsec/csv_reader.hpp"
namespace neonsec {
std::vector<std::string> split_csv(const std::string& line){
  std::vector<std::string> out; std::string cur; bool inq=false;
  for(size_t i=0;i<line.size();++i){
    char c=line[i];
    if(c==g_quote){ if(inq && i+1<line.size() && line[i+1]=='"'){ cur.push_back('"'); ++i; } else inq=!inq; }
    else if(c==',' && !inq){ out.push_back(cur); cur.clear(); }
    else cur.push_back(c);
  }
  out.push_back(cur); return out;
}
} // namespace neonsec
