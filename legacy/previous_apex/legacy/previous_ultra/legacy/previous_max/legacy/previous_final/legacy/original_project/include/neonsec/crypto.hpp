
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
namespace neonsec {
namespace crypto {
// Minimal SHA-256 (public-domain style implementation)
struct Sha256 {
  uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t blen;
  static inline uint32_t rotr(uint32_t x, int n){ return (x>>n)|(x<<(32-n)); }
  static inline uint32_t ch(uint32_t x,uint32_t y,uint32_t z){ return (x&y) ^ (~x&z); }
  static inline uint32_t maj(uint32_t x,uint32_t y,uint32_t z){ return (x&y) ^ (x&z) ^ (y&z); }
  static inline uint32_t bsig0(uint32_t x){ return rotr(x,2)^rotr(x,13)^rotr(x,22); }
  static inline uint32_t bsig1(uint32_t x){ return rotr(x,6)^rotr(x,11)^rotr(x,25); }
  static inline uint32_t ssig0(uint32_t x){ return rotr(x,7)^rotr(x,18)^(x>>3); }
  static inline uint32_t ssig1(uint32_t x){ return rotr(x,17)^rotr(x,19)^(x>>10); }
  static const uint32_t K[64];
  void init(){
    h[0]=0x6a09e667; h[1]=0xbb67ae85; h[2]=0x3c6ef372; h[3]=0xa54ff53a;
    h[4]=0x510e527f; h[5]=0x9b05688c; h[6]=0x1f83d9ab; h[7]=0x5be0cd19;
    len=0; blen=0;
  }
  void block(const uint8_t *p){
    uint32_t w[64];
    for(int i=0;i<16;++i){ w[i]=(p[4*i]<<24)|(p[4*i+1]<<16)|(p[4*i+2]<<8)|p[4*i+3]; }
    for(int i=16;i<64;++i){ w[i]=ssig1(w[i-2])+w[i-7]+ssig0(w[i-15])+w[i-16]; }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],_h=h[7];
    for(int i=0;i<64;++i){
      uint32_t t1=_h + bsig1(e) + ch(e,f,g) + K[i] + w[i];
      uint32_t t2=bsig0(a)+maj(a,b,c);
      _h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=_h;
  }
  void update(const void* data, size_t n){
    const uint8_t* p=(const uint8_t*)data;
    len += n*8;
    while(n>0){
      size_t take = (n > 64-blen) ? (64-blen) : n;
      std::memcpy(buf+blen, p, take);
      blen += take; p += take; n -= take;
      if(blen==64){ block(buf); blen=0; }
    }
  }
  void final(uint8_t out[32]){
    buf[blen++] = 0x80;
    if(blen > 56){ while(blen<64) buf[blen++]=0; block(buf); blen=0; }
    while(blen<56) buf[blen++]=0;
    for(int i=7;i>=0;--i){ buf[blen++] = (uint8_t)((len>>(8*i))&0xFF); }
    block(buf);
    for(int i=0;i<8;++i){
      out[4*i] = (uint8_t)(h[i]>>24);
      out[4*i+1] = (uint8_t)(h[i]>>16);
      out[4*i+2] = (uint8_t)(h[i]>>8);
      out[4*i+3] = (uint8_t)(h[i]);
    }
  }
};
const uint32_t Sha256::K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline std::string hmac_sha256_hex(const std::string& key, const std::string& msg){
  const size_t block=64;
  std::vector<uint8_t> k(block,0);
  if(key.size()>block){
    Sha256 hs; hs.init(); hs.update(key.data(), key.size()); uint8_t kh[32]; hs.final(kh);
    std::memcpy(k.data(), kh, 32);
  }else{
    std::memcpy(k.data(), key.data(), key.size());
  }
  std::vector<uint8_t> ipad(block,0x36), opad(block,0x5c);
  for(size_t i=0;i<block;++i){ ipad[i]^=k[i]; opad[i]^=k[i]; }
  Sha256 h1; h1.init(); h1.update(ipad.data(), ipad.size()); h1.update(msg.data(), msg.size()); uint8_t ih[32]; h1.final(ih);
  Sha256 h2; h2.init(); h2.update(opad.data(), opad.size()); h2.update(ih, 32); uint8_t oh[32]; h2.final(oh);
  static const char* X="0123456789abcdef"; std::string out; out.resize(64);
  for(int i=0;i<32;++i){ out[2*i]=X[(oh[i]>>4)&0xF]; out[2*i+1]=X[oh[i]&0xF]; }
  return out;
}
} // namespace crypto
} // namespace neonsec
