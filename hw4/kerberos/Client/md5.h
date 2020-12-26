#ifndef MD5_H_INCLUDED
#define MD5_H_INCLUDED


typedef struct md5_ctx {
	unsigned long int CV[4];		//寄存器(A,B,C,D)
	unsigned long long int count;   //原始消息数据的字节数
	unsigned char buffer[64];
}md5_ctx_t;

//初始化上下文结构体开始一个MD5操作
void md5_init(md5_ctx_t* ctx);
//计算除最后填充分组外的分组的摘要
void md5_update(md5_ctx_t* ctx, unsigned char* input , unsigned int inputLen);
//计算最后填充分组的摘要，得到结果HASH值
void md5_final(md5_ctx_t* ctx, unsigned char digest[16]);

//最终的md5算法
//input:任意不定长信息
//len:信息的长度（字节数）
//output:输出16个字节的信息摘要
void md5_digest(unsigned char* input, unsigned int iLen, unsigned char output[16]);

#endif // MD5_H_INCLUDED
