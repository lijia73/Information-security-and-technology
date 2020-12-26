#include <stdio.h>
#include "md5.h"
const unsigned char PADDING[64] = { 0x80 };

//轮函数
unsigned long int F(unsigned long int b, unsigned long int c, unsigned long int d) { return (b & c) | (~b & d); }
unsigned long int G(unsigned long int b, unsigned long int c, unsigned long int d) { return (b & d) | (c & ~d); }
unsigned long int H(unsigned long int b, unsigned long int c, unsigned long int d) { return b ^ c ^ d; }
unsigned long int I(unsigned long int b, unsigned long int c, unsigned long int d) { return c ^ (b | ~d); }
unsigned long int(*g[4])(unsigned long int, unsigned long int, unsigned long int) = { F, G, H, I };

//! 将x循环左移n位
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

const int X[4][16] = { 
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12},
	{5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2},
	{0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9}
};
const unsigned long int T[4][16] = {
	{0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821},
	{0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a},
	{0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9,0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665},
	{0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391}
};

const int S[4][16] = { 
	{ 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22 },
	{ 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20 },
	{ 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23 },
	{ 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 }
};

void md5_init(md5_ctx_t* ctx) {
	//初始化寄存器
	ctx->CV[0] = 0x67452301;
	ctx->CV[1] = 0xEFCDAB89;
	ctx->CV[2] = 0x98BADCFE;
	ctx->CV[3] = 0x10325476;
	ctx->count = 0;
}
//计算一个分组的摘要
void md5_transform(unsigned long int CV[4],unsigned char Y[64]) {
	int i, j ,t;
	unsigned long int a = CV[0], b = CV[1], c = CV[2], d = CV[3];
	//4轮循环
	for (i = 0; i < 4; i++) {
		//16轮迭代
		for (j = 0; j < 16; j++) {
			int k = X[i][j];
			//每次迭代处理消息分组的32位字
			unsigned long int y = 0;
			for (t = 0; t < 4; t++) {
				y |= ((unsigned long int)Y[4*k+t] << (t * 8));
			}
			//对 A 迭代
			a= b + ROTATE_LEFT(a + g[i](b, c, d) + y + T[i][j], S[i][j]);
			//缓冲区作循环置换
			unsigned long int temp = a;
			a = d;
			d = c;
			c = b;
			b = temp;
		}
	}
	CV[0] += a;
	CV[1] += b;
	CV[2] += c;
	CV[3] += d;

}

void md5_update(md5_ctx_t* ctx, unsigned char* input, unsigned int inputLen) {
	unsigned int index = ctx->count % 64;//缓冲区已有的字节数
	unsigned int partLen = 64 - index;//缓冲区还能容纳的字节数
	unsigned int i;
	if (inputLen >= partLen) {
		//填满缓冲区剩余部分并计算摘要
		memcpy(ctx->buffer + index, input, partLen);
		md5_transform(ctx->CV, ctx->buffer);
		//循环处理输入中间的整块部分
		for (i = partLen; i + 63 < inputLen; i += 64) {
			md5_transform(ctx->CV, input+i);
		}
		//将输入剩余部分填入缓冲区
		memcpy(ctx->buffer, input+i, inputLen-i);
	}
	else memcpy(ctx->buffer + index, input, inputLen);
	ctx->count += inputLen;
}

void md5_final(md5_ctx_t* ctx, unsigned char digest[16]) {
	unsigned int index = ctx->count % 64;//缓冲区已有的字节数
	unsigned int partLen = 64 - index;//缓冲区还能容纳的字节数
	unsigned int pi = 0,i,j;
	//不足以放下一位填充位，填充两块
	if (index >= 56) {
		memcpy(ctx->buffer + index, PADDING, partLen);
		pi += partLen;
		md5_transform(ctx->CV, ctx->buffer);
		index = 0;
	}
	//填充二进制序列
	memcpy(ctx->buffer + index, PADDING+pi, 56-index);
	//将 count 的低64位按 little-endian 转移成8个字节顺序填充 
	for (i = 0; i < 8; i++) {
		ctx->buffer[56 + i] = (unsigned char)(ctx->count*8 >> i * 8);//由于count是字节数，转换为位数需要*8
	}
	//计算最后一块的摘要
	md5_transform(ctx->CV, ctx->buffer);
	//对每个寄存器的值按little-endian转换为4个字节，总共16个字节，得出结果
	for(i = 0; i < 4; i++){
		for (j = 0; j < 4; j++) {
			digest[i * 4 + j] = (unsigned char)(ctx->CV[i] >> j * 8);
		}
	}
}

void md5_digest(unsigned char* input, unsigned int iLen, unsigned char output[16]) {
	md5_ctx_t ctx;

	md5_init(&ctx);//缓冲区初始化
	md5_update(&ctx, input, iLen);//分块
	md5_final(&ctx, output);//填充
}