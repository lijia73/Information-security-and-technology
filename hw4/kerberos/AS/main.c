#include <stdio.h>
#include <stdlib.h>
#include <sys/msg.h>
#include <string.h>
#include <time.h>
#include "des.h"
#include "md5.h"

// 用于创建一个唯一的key
#define MSG_FILE "/etc"

#define M_SIZE 256
// 消息结构
struct msg_form {
    long mtype;
    unsigned char mtext[M_SIZE];
};

unsigned char ktgs[8]="thisatgs";

struct userinfo{
    unsigned char username[50];
    unsigned char password[50];
    unsigned char masterkey[8];
};

int main()
{
    //Account Database
    struct userinfo userinfos[100];
    int userinfolength=1;
    strcpy(userinfos[0].username, "123");
    strcpy(userinfos[0].password, "123");
    unsigned char md5hash[16];
    md5_digest(userinfos[0].password,strlen((char*)userinfos[0].password),md5hash);
    memcpy(userinfos[0].masterkey,md5hash,8);

    int msqid;
    key_t key;
    struct msg_form msg;
    // 获取key值
    if((key = ftok(MSG_FILE,'z')) < 0)
    {
        perror("ftok error");
        exit(1);
    }

    // 打印key值
    printf("Message Queue - Server key is: %d.\n", key);
    // 创建消息队列
    msqid = msgget(key, IPC_CREAT|0777);
    //msgctl(msqid, IPC_RMID, 0);
    //msqid = msgget(key, IPC_CREAT|0777);

    // 打印消息队列ID及进程ID
    printf("My msqid is: %d.\n", msqid);
    printf("My pid is: %d.\n", getpid());

    // 循环读取消息
    for(;;)
    {
        //接收明文客户端id
        msgrcv(msqid, &msg, 256, 111, 0);// 返回类型为111的第一个消息
        printf("Server: receive clientid.mtext is: %s.\n", msg.mtext);
        printf("Server: receive clientid.mtype is: %ld.\n", msg.mtype);

        char client_id[50];
        sprintf(client_id, msg.mtext);
        //printf("strlen(client_id):%d\n",strlen(client_id));

        //接收明文用户名
        msgrcv(msqid, &msg, 256, 222, 0);// 返回类型为222的第一个消息
        printf("Server: receive username.mtext is: %s.\n", msg.mtext);
        printf("Server: receive username.mtype is: %ld.\n", msg.mtype);

        int find=0;
        unsigned char kclient[8];
        for(int i=0;i<userinfolength;i++){
            //printf("-------%d\n",strcmp((char*)userinfos[i].username,(char*)msg.mtext));
            if(strcmp((char*)userinfos[i].username,(char*)msg.mtext)==0){
                memcpy(kclient,userinfos[i].masterkey,8);
                find=1;
                break;
            }
        }
        //如果数据库不存在该用户 ID 的记录
        if(find==0){
            printf("Server: error,username can't found!\n");
            msg.mtype = 404; // 客户端接收的消息类型
            sprintf(msg.mtext, "error");
            msgsnd(msqid, &msg, sizeof(msg.mtext), 0);
            printf("-----------------------\n");
            continue;
        }
        msg.mtype = 404; // 客户端接收的消息类型
        sprintf(msg.mtext, "no error");
        msgsnd(msqid, &msg, sizeof(msg.mtext), 0);

        //随机生成会话密钥
        unsigned char kclient_tgs[8];
        srand((int)time(0));
        for(int i=0;i<8;i++){
            kclient_tgs[i]=rand()%128;
            //printf("%c",kclient_tgs[i]);
        }
        //printf("\n");

        //返回消息A
        printf("Server: send A\n");
        msg.mtype = 'A'; // 客户端接收的消息类型
        unsigned char messagea[8];
        Encrypt(kclient_tgs, 8,kclient, messagea);
        memcpy(msg.mtext, messagea,8);
        msgsnd(msqid, &msg, sizeof(msg.mtext), 0);

        //返回消息B
        printf("Server: send B\n");
        msg.mtype = 'B'; // 客户端接收的消息类型
        unsigned char messageb[100];
        unsigned char plain[100];
        memcpy(plain,kclient_tgs,8);
        memcpy(plain+8,client_id,strlen(client_id));
        int plainsize=8+strlen(client_id);
        int ciphersize=Encrypt(plain, plainsize,ktgs, messageb);
        memcpy(msg.mtext, messageb,ciphersize);
        msg.mtext[ciphersize]='\0';
        msgsnd(msqid, &msg, sizeof(msg.mtext), 0);

        printf("-----------------------\n");
    }
    return 0;
}
