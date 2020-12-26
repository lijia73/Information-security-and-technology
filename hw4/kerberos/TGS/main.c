#include <stdio.h>
#include <stdlib.h>
#include <sys/msg.h>
#include <string.h>
#include <time.h>
#include "des.h"

// 用于创建一个唯一的key
#define MSG_FILE "/usr"

#define M_SIZE 256
// 消息结构
struct msg_form {
    long mtype;
    unsigned char mtext[M_SIZE];
};

unsigned char ktgs[8]="thisatgs";
unsigned char kss[8]="thisanss";
int main()
{
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

    // 打印消息队列ID及进程ID
    printf("My msqid is: %d.\n", msqid);
    printf("My pid is: %d.\n", getpid());

    // 循环读取消息
    for(;;)
    {
        //接收消息C
        msgrcv(msqid, &msg, 256, 'C', 0);// 返回类型为111的第一个消息
        printf("Server: receive C.mtext is: %s.\n", msg.mtext);
        printf("Server: receive C.mtype is: %ld.\n", msg.mtype);

        unsigned char tgt[100];
        sprintf(tgt, msg.mtext);
        unsigned char plainc[100];
        int plaincsize=Decrypt(tgt,strlen(tgt),ktgs,plainc);
        plainc[plaincsize]='\0';
        unsigned char kclient_tgs[8];
        memcpy(kclient_tgs,plainc,8);
        unsigned char client_id_a[50];
        sprintf(client_id_a,"%s",plainc+8);

        //接收消息D
        msgrcv(msqid, &msg, 256, 'D', 0);// 返回类型为222的第一个消息
        printf("Server: receive D.mtext is: %s.\n", msg.mtext);
        printf("Server: receive D.mtype is: %ld.\n", msg.mtype);
        unsigned char plaind[100];
        int plaindsize=Decrypt(msg.mtext,strlen(msg.mtext),kclient_tgs,plaind);
        plaind[plaindsize]='\0';
        unsigned char timestamp[11];
        memcpy(timestamp,plaind,10);
        timestamp[10]='\0';
        long numtimestamp=0;
        sscanf(timestamp,"%ld",&numtimestamp);

        unsigned char client_id_b[50];
        sprintf(client_id_b,"%s",plaind+10);

        //检查消息C,D中的client信息是否一致
        if(strcmp(client_id_a,client_id_b)!=0){
            printf("Server: error,ST authentication failed\n");
            msg.mtype = 404; // 客户端接收的消息类型
            sprintf(msg.mtext, "error");
            msgsnd(msqid, &msg, sizeof(msg.mtext), 0);
            printf("-----------------------\n");
            continue;
        }
        //与当前时间比较，如果偏差超出一个可以接受的时间范围（5mins），Server会直接拒绝该Client的请求
        long nowtimestamp=time(NULL);
        if(nowtimestamp-numtimestamp>300){
            printf("Server: error,timeout\n");
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
        unsigned char kclient_ss[8];
        srand((int)time(0));
        for(int i=0;i<8;i++){
            kclient_ss[i]=rand()%128;
        }

        //返回消息F
        printf("Server: send F\n");
        msg.mtype = 'F'; // 客户端接收的消息类型
        unsigned char messagef[8];
        Encrypt(kclient_ss, 8,kclient_tgs, messagef);
        memcpy(msg.mtext, messagef,8);
        msgsnd(msqid, &msg, sizeof(msg.mtext), 0);


        //返回消息E
        printf("Server: send E\n");
        msg.mtype = 'E'; // 客户端接收的消息类型
        unsigned char messagee[100];
        unsigned char plain[100];
        memcpy(plain,kclient_ss,8);
        memcpy(plain+8,client_id_a,strlen(client_id_a));
        int plainsize=8+strlen(client_id_a);
        int ciphersize=Encrypt(plain, plainsize,kss, messagee);
        memcpy(msg.mtext, messagee,ciphersize);
        msg.mtext[ciphersize]='\0';
        msgsnd(msqid, &msg, sizeof(msg.mtext), 0);

        printf("-----------------------\n");
    }
    return 0;
}
