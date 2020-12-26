#include <stdio.h>
#include "md5.h"

void hmac_md5(unsigned char* k, unsigned int kLen, unsigned char* message, unsigned long int mLen, unsigned char* digest) {
	md5_ctx_t ictx, octx;
	unsigned int i;
	unsigned char key[16];
	unsigned char S[64];
	//�����Կ���ȴ���64�ֽڣ�����Ϊkey=MD5(key)
	if (kLen > 64) {
		md5_digest(k, kLen, key);
		k = key;
		kLen = 16;
	}
	//�Թ�����Կk�ұ߲�0������һ��64λ�����ݿ飬ͬʱ��ipad��XOR������S1 
	for (i = 0; i < kLen; i++) {
		S[i] = k[i] ^ 0x36;
	}
	for (i = kLen; i < 64; i++) {
		S[i] = 0x36;
	}
	//S1��M���ӽ���MD5ѹ������H1
	md5_init(&ictx);
	md5_update(&ictx, S, 64);
	md5_update(&ictx, message, mLen);
	md5_final(&ictx, digest);

	//�Թ�����Կk�ұ߲�0������һ��64λ�����ݿ飬ͬʱ��opad��XOR������S2 
	for (i = 0; i < kLen; i++) {
		S[i] = k[i] ^ 0x5C;
	}
	for (i = kLen; i < 64; i++) {
		S[i] = 0x5C;
	}
	//S2��H1���ӽ���MD5ѹ���õ����
	md5_init(&octx);
	md5_update(&octx, S, 64);
	md5_update(&octx, digest, 16);
	md5_final(&octx, digest);
}