#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>

void Char8ToBit64(unsigned char ch[8], unsigned char bit[64]);
void Bit64ToChar8(unsigned char bit[64], unsigned char ch[8]);
void GenerateSubKeys(unsigned char key[64], unsigned char subKeys[16][48]);
void PC1_Transform(unsigned char key[64], unsigned char tempbts[56]);
void PC2_Transform(unsigned char key[56], unsigned char tempbts[48]);
void RSL(unsigned char data[56], int time);
void IP_Transform(unsigned char data[64]);
void IP_1_Transform(unsigned char data[64]);
void E_Transform(unsigned char data[48]);
void P_Transform(unsigned char data[32]);
void S_BOX(unsigned char data[48]);
void XOR(unsigned char R[48], unsigned char L[48], int count);
void Swap(unsigned char left[32], unsigned char right[32]);
void EncryptBlock(unsigned char plainBlock[8], unsigned char subKeys[16][48], unsigned char cipherBlock[8]);
void DecryptBlock(unsigned char cipherBlock[8], unsigned char subKeys[16][48], unsigned char plainBlock[8]);
int Encrypt(unsigned char* plain, int plainsize, unsigned char* key, unsigned char* cipher);
int Decrypt(unsigned char* cipher, int ciphersize, unsigned char* key, unsigned char* plain);

//????????IP
int IP_Table[64] = { 57,49,41,33,25,17,9,1,
                                 59,51,43,35,27,19,11,3,
                                 61,53,45,37,29,21,13,5,
                                 63,55,47,39,31,23,15,7,
                                 56,48,40,32,24,16,8,0,
                                 58,50,42,34,26,18,10,2,
                                 60,52,44,36,28,20,12,4,
                                 62,54,46,38,30,22,14,6 };
//?????????IP^-1
int IP_1_Table[64] = { 39,7,47,15,55,23,63,31,
           38,6,46,14,54,22,62,30,
           37,5,45,13,53,21,61,29,
           36,4,44,12,52,20,60,28,
           35,3,43,11,51,19,59,27,
           34,2,42,10,50,18,58,26,
           33,1,41,9,49,17,57,25,
           32,0,40,8,48,16,56,24 };

//E-????????
int E_Table[48] = { 31, 0, 1, 2, 3, 4,
                  3,  4, 5, 6, 7, 8,
                  7,  8,9,10,11,12,
                  11,12,13,14,15,16,
                  15,16,17,18,19,20,
                  19,20,21,22,23,24,
                  23,24,25,26,27,28,
                  27,28,29,30,31, 0 };

//P-?????
int P_Table[32] = { 15,6,19,20,28,11,27,16,
                  0,14,22,25,4,17,30,9,
                  1,7,23,13,31,26,2,8,
                  18,12,29,5,21,10,3,24 };

//S-??
int S_b[8][4][16] =//S1
{ {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
  {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
    //S2
  {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
  {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
  {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
  {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
    //S3
    {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
    {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
      {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
    {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
    //S4
    {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
    //S5
    {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
    //S6
    {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
    {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
    //S7
    {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
    //S8
    {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}} };
//??????1
int PC_1[56] = { 56,48,40,32,24,16,8,
              0,57,49,41,33,25,17,
              9,1,58,50,42,34,26,
              18,10,2,59,51,43,35,
              62,54,46,38,30,22,14,
              6,61,53,45,37,29,21,
              13,5,60,52,44,36,28,
              20,12,4,27,19,11,3 };

//??????2
int PC_2[48] = { 13,16,10,23,0,4,2,27,
              14,5,20,9,22,18,11,3,
              25,7,15,6,26,19,12,1,
              40,51,30,36,46,54,29,39,
              50,44,32,46,43,48,38,55,
              33,52,45,41,49,35,28,31 };

//???????????涨
int MOVE_TIMES[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

//???????8???????????????λ??
void Char8ToBit64(unsigned char ch[8], unsigned char bit[64]) {
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            bit[i * 8 + j] = (ch[i] >> j) & 1;
        }
    }
}

//????????λ?????????8???????
void Bit64ToChar8(unsigned char bit[64], unsigned char ch[8]) {
    memset(ch, 0, 8);
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            ch[i] |= bit[i * 8 + j] << j;
        }
    }
}

//?????????
void GenerateSubKeys(unsigned char key[64], unsigned char subKeys[16][48]) {
    unsigned char temp[56];
    PC1_Transform(key, temp);//PC1???
    for (int cnt = 0; cnt < 16; cnt++) {//16???????????16???????
        RSL(temp, MOVE_TIMES[cnt]);//???????
        PC2_Transform(temp, subKeys[cnt]);//PC2??????????????
    }
}

//??????1
void PC1_Transform(unsigned char key[64], unsigned char tempbts[56]) {
    for (int cnt = 0; cnt < 56; cnt++) {
        tempbts[cnt] = key[PC_1[cnt]];
    }
}

//??????2
void PC2_Transform(unsigned char key[56], unsigned char tempbts[48]) {
    for (int cnt = 0; cnt < 48; cnt++) {
        tempbts[cnt] = key[PC_2[cnt]];
    }
}

//???????
void RSL(unsigned char data[56], int time) {
    unsigned char tempa[2], tempb[2];

    //???潫?????????????λ
    memcpy(tempa, data, time);
    memcpy(tempb, data + 28, time);

    //?28λ???
    memcpy(data, data + time, 28 - time);
    memcpy(data + 28 - time, tempa, time);

    //??28λ???
    memcpy(data + 28, data + 28 + time, 28 - time);
    memcpy(data + 56 - time, tempb, time);
}

//IP???
void IP_Transform(unsigned char data[64]) {
    unsigned char temp[64];
    for (int cnt = 0; cnt < 64; cnt++) {
        temp[cnt] = data[IP_Table[cnt]];
    }
    memcpy(data, temp, 64);
}

//IP?????
void IP_1_Transform(unsigned char data[64]) {
    unsigned char temp[64];
    for (int cnt = 0; cnt < 64; cnt++) {
        temp[cnt] = data[IP_1_Table[cnt]];
    }
    memcpy(data, temp, 64);
}

//??????
void E_Transform(unsigned char data[48]) {
    unsigned char temp[48];
    for (int cnt = 0; cnt < 48; cnt++) {
        temp[cnt] = data[E_Table[cnt]];
    }
    memcpy(data, temp, 48);
}

//P???
void P_Transform(unsigned char data[32]) {
    unsigned char temp[32];
    for (int cnt = 0; cnt < 32; cnt++) {
        temp[cnt] = data[P_Table[cnt]];
    }
    memcpy(data, temp, 32);
}

//???
void XOR(unsigned char R[48], unsigned char L[48], int count) {
    for (int cnt = 0; cnt < count; cnt++) {
        R[cnt] ^= L[cnt];
    }
}

//S?????
void S_BOX(unsigned char data[48]) {
    int row, col, output;
    int cur1, cur2;
    for (int cnt = 0; cnt < 8; cnt++) {
        cur1 = cnt * 6;
        cur2 = cnt << 2;

        //??????S???е???????
        row = (data[cur1] << 1) + data[cur1 + 5];
        col = (data[cur1 + 1] << 3) + (data[cur1 + 2] << 2)
            + (data[cur1 + 3] << 1) + data[cur1 + 4];
        output = S_b[cnt][row][col];

        //???2????
        data[cur2] = (output & 0X08) >> 3;
        data[cur2 + 1] = (output & 0X04) >> 2;
        data[cur2 + 2] = (output & 0X02) >> 1;
        data[cur2 + 3] = output & 0x01;
    }
}

//????
void Swap(unsigned char left[32], unsigned char right[32]) {
    unsigned char temp[32];
    memcpy(temp, left, 32);
    memcpy(left, right, 32);
    memcpy(right, temp, 32);
}

//???????????
void EncryptBlock(unsigned char plainBlock[8], unsigned char subKeys[16][48], unsigned char cipherBlock[8]) {
    unsigned char plainBits[64];
    unsigned char R[48];

    //??????????ASCII?????????64λ????
    Char8ToBit64(plainBlock, plainBits);
    //????????IP?????
    IP_Transform(plainBits);

    //16?????
    for (int cnt = 0; cnt < 16; cnt++) {
        //R
        memcpy(R, plainBits + 32, 32);
        //???????R??????????????32λ?????48λ
        E_Transform(R);
        //??????????????????????????
        XOR(R, subKeys[cnt], 48);
        //?????????S?У????32λ???
        S_BOX(R);
        //32λ???????P-???
        P_Transform(R);
        //???????????L???????R???????????????L
        XOR(plainBits, R, 32);
        if (cnt != 15) {
            //?????????????????
            Swap(plainBits, plainBits + 32);
        }
    }
    //?????????IP^1?????
    IP_1_Transform(plainBits);
    //????????64λ???????? ASCII?????
    Bit64ToChar8(plainBits, cipherBlock);
}

//???????????
void DecryptBlock(unsigned char cipherBlock[8], unsigned char subKeys[16][48], unsigned char plainBlock[8]) {
    unsigned char cipherBits[64];
    unsigned char R[48];

    Char8ToBit64(cipherBlock, cipherBits);
    IP_Transform(cipherBits);

    //????????????????????????????н???????????K16??K15??????K1???????
    for (int cnt = 15; cnt >= 0; cnt--) {
        memcpy(R, cipherBits + 32, 32);
        E_Transform(R);
        XOR(R, subKeys[cnt], 48);
        S_BOX(R);
        P_Transform(R);
        XOR(cipherBits, R, 32);
        if (cnt != 0) {
            Swap(cipherBits, cipherBits + 32);
        }
    }
    IP_1_Transform(cipherBits);
    Bit64ToChar8(cipherBits, plainBlock);
}

//???????
int Encrypt(unsigned char* plain, int plainsize, unsigned char* key, unsigned char* cipher) {
    unsigned char plainBlock[8], cipherBlock[8], keyBlock[8];
    unsigned char bKey[64];
    unsigned char subKeys[16][48];
    int ciphersize=0;
    memcpy(keyBlock, key, 8);
    Char8ToBit64(keyBlock, bKey);
    GenerateSubKeys(bKey, subKeys);

    while (plainsize >= 8) {
        memcpy(plainBlock, plain, 8);
        plain += 8;
        plainsize -= 8;
        EncryptBlock(plainBlock, subKeys, cipherBlock);
        memcpy(cipher, cipherBlock, 8);
        cipher += 8;
        ciphersize += 8;
    }
    if (plainsize) {
        memcpy(plainBlock, plain, plainsize);
        memset(plainBlock + plainsize, 8, 7 - plainsize);
        plainBlock[7] = 8 - plainsize;
        EncryptBlock(plainBlock, subKeys, cipherBlock);
        memcpy(cipher, cipherBlock, 8);
        ciphersize += 8;
    }
    return ciphersize;
}

//???????
int Decrypt(unsigned char* cipher, int ciphersize, unsigned char* key, unsigned char* plain) {
    int count = 0;
    unsigned char plainBlock[8], cipherBlock[8], keyBlock[8];
    unsigned char bKey[64];
    unsigned char subKeys[16][48];
    int plainsize=0;
    memcpy(keyBlock, key, 8);
    Char8ToBit64(keyBlock, bKey);
    GenerateSubKeys(bKey, subKeys);
    while (1) {
        memcpy(cipherBlock, cipher, 8);
        cipher += 8;
        ciphersize -= 8;
        DecryptBlock(cipherBlock, subKeys, plainBlock);

        if (ciphersize >= 8) {
            memcpy(plain, plainBlock, 8);
            plainsize += 8;
            plain += 8;
        }
        else {
            break;
        }
    }
    if (plainBlock[7] < 8) {
        for (count = 8 - plainBlock[7]; count < 7; count++) {
            if (plainBlock[count] != 8) {
                break;
            }
        }
    }
    if (count == 7) {
        memcpy(plain, plainBlock, 8 - plainBlock[7]);
        plainsize += 8 - plainBlock[7];
    }
    else {
        memcpy(plain, plainBlock, 8);
        plainsize += 8;
    }
    return plainsize;
}
