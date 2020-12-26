#include <stdio.h>
#include <stdlib.h>
#include <sys/msg.h>
#include <string.h>
#include <time.h>
#include "des.h"

// 用于创建一个唯一的key
#define MSG_FILE "/bin"

#define M_SIZE 256
// 消息结构
struct msg_form {
    long mtype;
    unsigned char mtext[M_SIZE];
};

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

        //接收消息E
        msgrcv(msqid, &msg, 256, 'E', 0);// 返回类型为111的第一个消息
        printf("Server: receive E.mtext is: %s.\n", msg.mtext);
        printf("Server: receive E.mtype is: %ld.\n", msg.mtype);

        unsigned char st[100];
        sprintf(st, msg.mtext);
        unsigned char plaine[100];
        int plainesize=Decrypt(st,strlen(st),kss,plaine);
        plaine[plainesize]='\0';
        unsigned char kclient_ss[8];
        memcpy(kclient_ss,plaine,8);
        unsigned char client_id_a[50];
        sprintf(client_id_a,"%s",plaine+8);

        //接收消息G
        msgrcv(msqid, &msg, 256, 'G', 0);// 返回类型为222的第一个消息
        printf("Server: receive G.mtext is: %s.\n", msg.mtext);
        printf("Server: receive G.mtype is: %ld.\n", msg.mtype);
        unsigned char plaing[100];
        int plaingsize=Decrypt(msg.mtext,strlen(msg.mtext),kclient_ss,plaing);
        plaing[plaingsize]='\0';
        unsigned char timestamp[11];
        memcpy(timestamp,plaing,10);
        timestamp[10]='\0';
        long numtimestamp=0;
        sscanf(timestamp,"%ld",&numtimestamp);
        unsigned char client_id_b[50];
        sprintf(client_id_b,"%s",plaing+10);

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

        //检查消息C,D中的client信息是否一致
        if(strcmp(client_id_a,client_id_b)!=0){
            printf("Server: error,authentication failed\n");
            msg.mtype = 404; // 客户端接收的消息类型
            sprintf(msg.mtext, "error");
            msgsnd(msqid, &msg, sizeof(msg.mtext), 0);
            printf("-----------------------\n");
            continue;
        }
        msg.mtype = 404; // 客户端接收的消息类型
        sprintf(msg.mtext, "no error");
        msgsnd(msqid, &msg, sizeof(msg.mtext), 0);

        //timestamp+1
        numtimestamp++;
        //返回消息H
        printf("Server: send H\n");
        msg.mtype = 'H'; // 客户端接收的消息类型
        unsigned char messageh[100];
        unsigned char plainh[100];
        sprintf(plainh,"%ld%s",numtimestamp,client_id_a);
        int hciphersize=Encrypt(plainh, strlen(plainh),kclient_ss, messageh);
        memcpy(msg.mtext, messageh,hciphersize);
        msg.mtext[hciphersize]='\0';
        msgsnd(msqid, &msg, sizeof(msg.mtext), 0);

        printf("-----------------------\n");
    }
    return 0;
}
