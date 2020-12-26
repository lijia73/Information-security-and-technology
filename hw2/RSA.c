#include <stdio.h> 
#include <stdlib.h>
#include <io.h> 
#include <memory.h>
#include <time.h>
#include <gmp.h>
#include<string.h>

#define BASE 16
#define N 1024
#define k 128



typedef struct {
	int e;
	char* d;
	char* n;
}key_value;


mpz_t* GET_BIG_PRIME_N();
key_value* RSAES_PKCS1_V1_5_GNERATE_KEY();
void RSAES_PKCS1_V1_5_ENCODE(char* M,char EM[k]);
void RSAES_PKCS1_V1_5_DECODE(char EM[k],char* M);
char* RSAES_PKCS1_OS2IP(char S[k]);
char* RSAES_PKCS1_I2OSP(char* number);
char* RSAES_PKCS1_V1_5_ENCRYPT(int e,const char* n,char EM[k]);
char* RSAES_PKCS1_V1_5_DECRYPT(const char* d, const char* n, char C[k]);

int hexcharToInt(char c)

{

	if (c >= '0' && c <= '9') return (c - '0');

	if (c >= 'A' && c <= 'F') return (c - 'A' + 10);

	if (c >= 'a' && c <= 'f') return (c - 'a' + 10);

	return 0;

}

void bytesToHexstring(char* bytes,char* hexstring,int bytelength)
{
	int hexstrlength = bytelength * 2;
	int i,j;
	char str2[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	for (i = 0, j = 0; i < bytelength, j < hexstrlength; i++, j++)
	{
		int b;
		b = 0x0f & (bytes[i] >> 4);
		char s1 = str2[b];
		hexstring[j] = s1;
		b = 0x0f & bytes[i];
		char s2 = str2[b];
		j++;
		hexstring[j] = s2;
	}
}

void hexstringToBytes(char* hexstring, char* bytes, int hexlength)
{
	int i;
	for (i = 0; i < hexlength; i += 2) {
		bytes[i / 2] = (char)((hexcharToInt(hexstring[i]) << 4)| hexcharToInt(hexstring[i + 1]));
	}
}


char* RSAES_PKCS1_OS2IP(char* S) {
	char* number = (char*)malloc(sizeof(char) * (2 * k + 10));
	bytesToHexstring(S, number, k);
	number[k * 2] = '\0';
	return number;
}

char* RSAES_PKCS1_I2OSP(char* number) {
	char* S = (char*)malloc(sizeof(char) * (k + 10));
	hexstringToBytes(number, S, k * 2);
	//S[k] = '\0';
	return S;
}

mpz_t* GET_BIG_PRIME_N() {
	//�������������
	gmp_randstate_t grt;
	gmp_randinit_default(grt);
	gmp_randseed_ui(grt, time(NULL));

	//��ʼ��
	mpz_t key_p, key_q;
	mpz_init(key_p);
	mpz_init(key_q);

	mpz_rrandomb(key_p, grt, N / 2);
	mpz_rrandomb(key_q, grt, N / 2);	//�����������������

	mpz_t* result = (mpz_t*)malloc(sizeof(mpz_t)*2);
	mpz_init(result[0]);
	mpz_init(result[1]);

	mpz_nextprime(result[0], key_p);  //ʹ��GMP�Դ����������ɺ���
	mpz_nextprime(result[1], key_q);

	mpz_clear(key_p);
	mpz_clear(key_q);

	return result;

}

key_value* RSAES_PKCS1_V1_5_GNERATE_KEY() {
	mpz_t* primes = GET_BIG_PRIME_N();
	mpz_t e, d, n, f;
	mpz_init_set_ui(e, 65537);
	mpz_init(d);
	mpz_init(n);
	mpz_init(f);
	
	//ȷ��n��λ��ΪN

	 do{
		mpz_clear(primes[0]);
		mpz_clear(primes[1]);
		free(primes);
		primes = GET_BIG_PRIME_N();
		mpz_mul(n, primes[0], primes[1]); //n=p*q
		//printf("%d\n", mpz_sizeinbase(n, 2));
	 } while (mpz_sizeinbase(n, 2) != N);


	 mpz_sub_ui(primes[0], primes[0], 1);		//p=p-1
	 mpz_sub_ui(primes[1], primes[1], 1);		//q=q-1
	 mpz_mul(f, primes[0], primes[1]);		//����ŷ��������(n)=(p-1)*(q-1)

	 mpz_invert(d, e, f); //��e��ģ��(n)�µĳ˷���Ԫ��Ҳ����Ϊ���۵�����d

	 char* buf_n = (char*)malloc(sizeof(char) * (N + 10));
	 char* buf_d = (char*)malloc(sizeof(char) * (N + 10));
	 mpz_get_str(buf_n, BASE, n);
	 mpz_get_str(buf_d, BASE, d);

	 key_value* result = (key_value*)malloc(sizeof(key_value));
	 result->e = 65537;
	 result->d = buf_d;
	 result->n = buf_n;

	 mpz_clear(primes[0]);   //�ͷ��ڴ�
	 mpz_clear(primes[1]);
	 mpz_clear(n);
	 mpz_clear(d);
	 mpz_clear(e);
	 mpz_clear(f);
	 free(primes);

	 return result;
}
void RSAES_PKCS1_V1_5_ENCODE(char* M, char EM[k]) {
	int mlen = strlen(M);
	int i;
	EM[0] = 0;
	EM[1] = 2;
	srand((unsigned)time(NULL));
	for (i = 2; i < k - mlen - 1; i++) {
		EM[i] = (char)(rand() % 127 + 1);
	}
	EM[k - mlen -1] = 0;
	
	for (i = 0; i < mlen; i++) {
		EM[k - mlen + i] = M[i];
	}

}
void RSAES_PKCS1_V1_5_DECODE(char EM[k], char* M) {
	int i;
	int start = 0;
	for (i = 2; i < k; i++) {
		if ((int)EM[i] == 0) {
			start = i+1;
			break;
		}
	}
	for (i = start; i < k; i++) {
		M[i - start] = EM[i];
	}
	M[i - start] = '\0';
}
char* RSAES_PKCS1_V1_5_ENCRYPT(int e, const char* n, char* M) {
	//������M���б�������EM 
	char EM[k]; 
	RSAES_PKCS1_V1_5_ENCODE(M, EM);
	//������������EMת��Ϊ��������m 
	char* m = RSAES_PKCS1_OS2IP(EM);
	
	mpz_t num_m, num_c, num_n;
	mpz_init_set_str(num_m, m, BASE);
	mpz_init_set_str(num_n, n, BASE);
	mpz_init(num_c);
	//ʹ��GMP��ģ�ݼ��㺯�������ù�Կ(e, N)������������m���ܣ��õ���������c
	mpz_powm_ui(num_c, num_m, e, num_n);    
	//��������c 
	char* c = (char*)malloc(sizeof(char) * (2 * k + 10));
	mpz_get_str(c, BASE, num_c);
	
	//����������cת��Ϊ����C
	char* C = RSAES_PKCS1_I2OSP(c);
	
	mpz_clear(num_m);
	mpz_clear(num_c);
	mpz_clear(num_n);
	return C;
}
char* RSAES_PKCS1_V1_5_DECRYPT(const char* d, const char* n, char* C) {
	//������Cת��Ϊ��������c
	char* c = RSAES_PKCS1_OS2IP(C);
	mpz_t num_m, num_c, num_d, num_n;
	mpz_init_set_str(num_c, c, BASE);
	mpz_init_set_str(num_d, d, BASE);
	mpz_init_set_str(num_n, n, BASE);
	mpz_init(num_m);
	//ʹ��GMP��ģ�ݼ��㺯��������˽Կ(d, N)������������c���ܣ��õ���������m 
	mpz_powm(num_m, num_c, num_d, num_n);    
	//��������m 
	char* m = (char*)malloc(sizeof(char) * (2 * k + 10));
	mpz_get_str(m, BASE, num_m);
	
	char* temp = (char*)malloc(sizeof(char) * (2 * k + 10));
	//������㶪ʧ�ĸ�λ0���� 
	temp[0]= temp[1]= temp[2] ='0' ;
	temp[3] = '\0';
	strcat(temp, m);
	
	//����������mת��Ϊ��������ϢEM 
	char* EM = RSAES_PKCS1_I2OSP(temp);
	char* M= (char*)malloc(sizeof(char) * (k + 10));
	//���� 
	RSAES_PKCS1_V1_5_DECODE(EM, M);
	
	mpz_clear(num_m);
	mpz_clear(num_c);
	mpz_clear(num_d);
	mpz_clear(num_n);
	return M;
}



int main(){
	key_value* p = RSAES_PKCS1_V1_5_GNERATE_KEY();
	printf("n = %s\n", p->n);
	printf("d = %s\n", p->d);
	printf("e = %d\n", p->e);
	
	char *input= (char*)malloc(sizeof(char) * (k+10));
	printf("Please input the string with length <= %d\n",k-11);
	gets(input);
	char* cipher_text = RSAES_PKCS1_V1_5_ENCRYPT(p->e, p->n, input);
	printf("cipher-text(every octet):");
	for (int i = 0; i < k; i++) {
		printf("%d ", (int)cipher_text[i]);
	}
	printf("\n");
	char* plain_text = RSAES_PKCS1_V1_5_DECRYPT(p->d, p->n,cipher_text);
	printf("plain-text:%s\n",plain_text);
	if (strcmp(input, plain_text) != 0)printf("-Fail");
	else printf("-Success");
	
	free(input);
	return 0;
}
