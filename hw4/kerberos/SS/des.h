#ifndef DES_H_INCLUDED
#define DES_H_INCLUDED

int Encrypt(unsigned char* plain, int plainsize, unsigned char* key, unsigned char* cipher);
int Decrypt(unsigned char* cipher, int ciphersize, unsigned char* key, unsigned char* plain);
#endif // DES_H_INCLUDED
