#!/usr/bin/env python3
import random, time, sys
n = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
print("ts,src_ip,dst_ip,dst_port,protocol,action,status,bytes,username")
t = int(time.time())
for i in range(n):
    print(f"{t+i%60},10.0.0.{i%256},10.0.1.{(i*7)%256},{(i%65535)+1},TCP,connect,ok,{(i%1500)+60},user{i%1000}")
