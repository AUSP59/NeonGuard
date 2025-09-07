/* SPDX-License-Identifier: Apache-2.0 */
#include "neonsec/c_api.h"
#include <stdio.h>
int main(){
  neonsec_engine* e = neonsec_engine_new(60, 20, 5, 500, 100, 3.5);
  neonsec_log_record r = {1725499200, "10.0.0.1", "10.0.0.2", 65000, "TCP", "connect", "ok", 128, "root"};
  neonsec_finding out[8];
  int n = neonsec_engine_feed(e, &r, out, 8);
  for(int i=0;i<n;++i){
    printf("[%lld] %s key=%s details=%s\n", (long long)out[i].ts, out[i].type, out[i].key, out[i].details);
  }
  neonsec_engine_free(e);
  return 0;
}
