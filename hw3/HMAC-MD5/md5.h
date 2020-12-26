#pragma once

typedef struct md5_ctx {
	unsigned long int CV[4];		//�Ĵ���(A,B,C,D)
	unsigned long long int count;   //ԭʼ��Ϣ���ݵ��ֽ���
	unsigned char buffer[64];
}md5_ctx_t;

//��ʼ�������Ľṹ�忪ʼһ��MD5����
void md5_init(md5_ctx_t* ctx);
//����������������ķ����ժҪ
void md5_update(md5_ctx_t* ctx, unsigned char* input , unsigned int inputLen);
//��������������ժҪ���õ����HASHֵ
void md5_final(md5_ctx_t* ctx, unsigned char digest[16]);

//���յ�md5�㷨
//input:���ⲻ������Ϣ
//len:��Ϣ�ĳ��ȣ��ֽ�����
//output:���16���ֽڵ���ϢժҪ
void md5_digest(unsigned char* input, unsigned int iLen, unsigned char output[16]);