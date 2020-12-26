#include <stdio.h>
#include <string.h>
#include "md5.h"
int main() {
    unsigned char* md5input[7] = {
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890" };

    unsigned char* md5expect[7] = {
        "d41d8cd98f00b204e9800998ecf8427e", "0cc175b9c0f1b6a831c399e269772661",
        "900150983cd24fb0d6963f7d28e17f72", "f96b697d7cb7938d525a2f31aaf161d0",
        "c3fcd3d76192e4007dfb496cca67e13b", "d174ab98d277d9f5a5611c2c9f419d9f",
        "57edf4a22be3c955ac49da2e2107b67a" };

    unsigned char* hmacdata[7] = {
        "Hi There",
        "what do ya want for nothing?",
        "",
        "",
        "Test With Truncation",
        "Test Using Larger Than Block-Size Key - Hash Key First",
        "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    };
    int i;
    unsigned char dt1[50],dt2[50];
    for (i = 0; i < 50; i++) {
        dt1[i] = 0xdd;
    }
    hmacdata[2] = dt1;
    for (i = 0; i < 50; i++) {
        dt2[i] = 0xcd;
    }
    hmacdata[3] = dt2;

    unsigned char* hmackey[7];
    unsigned char temp1[16];
    unsigned char temp2[16];
    unsigned char temp3[25]={ 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19 };
    unsigned char temp4[16];
    unsigned char temp5[80];
    for (i = 0; i < 16; i++) {
        temp1[i] = 0x0b;
        temp2[i] = 0xaa;
        temp4[i] = 0x0c;
    }
    for (i = 0; i < 80; i++) {
        temp5[i] = 0xaa;
    }

    hmackey[0] = temp1;
    hmackey[2] = temp2;
    hmackey[1] = "Jefe";
    hmackey[3] = temp3;
    hmackey[4] = temp4;
    hmackey[5] = temp5;
    hmackey[6] = temp5;
    
    unsigned int* hmackeyLen[7] = {
    16,
    4,
    16,
    25,
    16,
    80,
    80
    };

    unsigned int* hmacdataLen[7] = {
    8,
    28,
    50,
    50,
    20,
    54,
    73
    };

    unsigned char* hmacexpect[7] = {
        "9294727a3638bb1c13f48ef8158bfc9d",
        "750c783e6ab0b503eaa86e310a5db738",
        "56be34521d144c88dbb8c733f0e8b3f6",
        "697eaf0aca3a3aea3a75164746ffaa79",
        "56461ef2342edc00f9bab995690efd4c",
        "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
        "6f630fad67cda0ee1fb1f562db3aa53e"
    };

    for (int i = 0; i < 7; ++i) {
        unsigned char digest[16];
        md5_digest(md5input[i], strlen(md5input[i]),digest);
        printf("---------------MD5-----------------\n");
        printf("Test %d:\n", i);
        printf("Message : %s\n",md5input[i]);
        printf("Expected: %s\n", md5expect[i]);
        printf("Result  : ");
        for (int i = 0; i < 16; ++i) {
            printf("%02x", digest[i]);
        }
        printf("\n");
    }
    for (int i = 0; i < 7; ++i) {
        unsigned char digest[16];
        hmac_md5(hmackey[i], hmackeyLen[i], hmacdata[i], hmacdataLen[i], digest);
        printf("---------------HMAC-----------------\n");
        printf("Test %d:\n", i);
        printf("Message : %s\n", hmacdata[i]);
        printf("Expected: %s\n", hmacexpect[i]);
        printf("Result  : ");
        for (int i = 0; i < 16; ++i) {
            printf("%02x", digest[i]);
        }
        printf("\n");
    }

    return 0;
}