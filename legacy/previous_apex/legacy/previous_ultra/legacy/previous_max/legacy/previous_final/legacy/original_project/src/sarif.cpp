// SPDX-License-Identifier: Apache-2.0
#include "neonsec/sarif.hpp"
#include "neonsec/reporters.hpp"
#include <fstream>
namespace neonsec {
bool write_sarif(const std::string& path, const std::vector<Finding>& fs){
  std::ofstream f(path); if(!f) return false;
  f << "{\n  \"version\": \"2.1.0\",\n  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n  \"runs\": [ {\n    \"tool\": { \"driver\": { \"name\": \"neonsec\" } },\n    \"results\": [\n";
  for(size_t i=0;i<fs.size();++i){ const auto& r=fs[i];
    f << "      { \"ruleId\": \"" << json_escape(r.type) << "\", \"message\": { \"text\": \"" << json_escape(r.details) << "\" }, \"level\": \"warning\", \"locations\": [ { \"physicalLocation\": { \"artifactLocation\": { \"uri\": \"" << json_escape(r.key) << "\" } } } ], \"properties\": { \"ts\": " << r.ts << " } }";
    if(i+1<fs.size()) f << ","; f << "\n"; }
  f << "    ]\n  } ]\n}\n"; return true;
}
} // namespace neonsec
