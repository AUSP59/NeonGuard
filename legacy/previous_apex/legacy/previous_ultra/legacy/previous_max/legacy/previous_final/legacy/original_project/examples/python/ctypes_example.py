# SPDX-License-Identifier: Apache-2.0
# Minimal Python example using ctypes to call the C API
import ctypes, os, sys
libname = {
  'linux': 'libneonsec_c.so',
  'darwin': 'libneonsec_c.dylib',
  'win32': 'neonsec_c.dll'
}[sys.platform if sys.platform!='linux' else 'linux']
libpath = os.path.join('build', libname)
lib = ctypes.CDLL(libpath)

class Log(ctypes.Structure):
    _fields_ = [('ts', ctypes.c_longlong),
                ('src_ip', ctypes.c_char_p), ('dst_ip', ctypes.c_char_p),
                ('dst_port', ctypes.c_int), ('protocol', ctypes.c_char_p),
                ('action', ctypes.c_char_p), ('status', ctypes.c_char_p),
                ('bytes', ctypes.c_longlong), ('username', ctypes.c_char_p)]
class Finding(ctypes.Structure):
    _fields_ = [('type', ctypes.c_char*64), ('key', ctypes.c_char*64),
                ('details', ctypes.c_char*128), ('ts', ctypes.c_longlong)]

lib.neonsec_engine_new.restype = ctypes.c_void_p
e = lib.neonsec_engine_new(60,20,5,500,100,3.5)
rec = Log(1725499200, b"10.0.0.1", b"10.0.0.2", 65000, b"TCP", b"connect", b"ok", 128, b"root")
out = (Finding*8)()
n = lib.neonsec_engine_feed(ctypes.c_void_p(e), ctypes.byref(rec), out, 8)
for i in range(n):
    f = out[i]
    print(f"[{f.ts}] {bytes(f.type).split(b'\0',1)[0].decode()} key={bytes(f.key).split(b'\0',1)[0].decode()} details={bytes(f.details).split(b'\0',1)[0].decode()}")
