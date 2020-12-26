#include <stdio.h>
#include "md5.h"

void hmac_md5(unsigned char* k, unsigned int kLen, unsigned char* message, unsigned long int mLen, unsigned char* digest) {
	md5_ctx_t ictx, octx;
	unsigned int i;
	unsigned char key[16];
	unsigned char S[64];
	//如果密钥长度大于64字节，重设为key=MD5(key)
	if (kLen > 64) {
		md5_digest(k, kLen, key);
		k = key;
		kLen = 16;
	}
	//对共享密钥k右边补0，生成一个64位的数据块，同时与ipad作XOR，生成S1 
	for (i = 0; i < kLen; i++) {
		S[i] = k[i] ^ 0x36;
	}
	for (i = kLen; i < 64; i++) {
		S[i] = 0x36;
	}
	//S1与M连接进行MD5压缩生成H1
	md5_init(&ictx);
	md5_update(&ictx, S, 64);
	md5_update(&ictx, message, mLen);
	md5_final(&ictx, digest);

	//对共享密钥k右边补0，生成一个64位的数据块，同时与opad作XOR，生成S2 
	for (i = 0; i < kLen; i++) {
		S[i] = k[i] ^ 0x5C;
	}
	for (i = kLen; i < 64; i++) {
		S[i] = 0x5C;
	}
	//S2与H1连接进行MD5压缩得到结果
	md5_init(&octx);
	md5_update(&octx, S, 64);
	md5_update(&octx, digest, 16);
	md5_final(&octx, digest);
}