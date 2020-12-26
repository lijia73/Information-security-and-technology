#include <stdio.h>
#include <stdlib.h>
#include <sys/msg.h>
#include <string.h>
#include "md5.h"
// key for message queue with AS
#define MSG_FILE1 "/etc"
// key for message queue with TGS
#define MSG_FILE2 "/usr"
// key for message queue with SS
#define MSG_FILE3 "/bin"

#define M_SIZE 256

// 消息结构
struct msg_form {
    long mtype;
    unsigned char mtext[M_SIZE];
};


char client_id[50]="1";


int main()
{
    int msqid1,msqid2,msqid3;
    key_t key1,key2,key3;
   // 获取key值
    if ((key1 = ftok(MSG_FILE1, 'z')) < 0)
    {
    perror("ftok error");
    exit(1);
    }

    if ((key2 = ftok(MSG_FILE2, 'z')) < 0)
    {
    perror("ftok error");
    exit(1);
    }

    if ((key3 = ftok(MSG_FILE3, 'z')) < 0)
    {
    perror("ftok error");
    exit(1);
    }

    // 打印key值
    printf("Message Queue 1 - Client key is: %d.\n", key1);
    printf("Message Queue 2 - Client key is: %d.\n", key2);
    printf("Message Queue 3 - Client key is: %d.\n", key3);

    // 打开消息队列
    if ((msqid1 = msgget(key1, IPC_CREAT|0777)) == -1)
    {
        perror("msgget error");
        exit(1);
    }

    if ((msqid2 = msgget(key2, IPC_CREAT|0777)) == -1)
    {
        perror("msgget error");
        exit(1);
    }

    if ((msqid3 = msgget(key3, IPC_CREAT|0777)) == -1)
    {
        perror("msgget error");
        exit(1);
    }

    // 打印消息队列ID及进程ID
    printf("My msqid1 is: %d.\n", msqid1);
    printf("My msqid2 is: %d.\n", msqid2);
    printf("My msqid3 is: %d.\n", msqid3);
    printf("My pid is: %d.\n", getpid());


    for(;;){
        char username[50];
        char password[50];
        char masterkey[8];
        printf("Input username:\n");
        scanf("%s",username);
        printf("Input password:\n");
        scanf("%s",password);
        unsigned char md5hash[16];
        md5_digest(password, strlen(password),md5hash);
        unsigned char kclient[8];
        memcpy(kclient,md5hash,8);
        memcpy(masterkey,md5hash,8);

        struct msg_form msg;

        //Client向AS发送一个明文消息(用户名+客户端id)，代表用户请求服务。

        //发送客户端id
        //添加消息，类型为111
        printf("Client: send clientid\n");
        msg.mtype = 111;
        sprintf(msg.mtext,client_id);
        msgsnd(msqid1, &msg, sizeof(msg.mtext), 0);

        //发送用户名
        //添加消息，类型为222
        printf("Client: send username\n");
        msg.mtype = 222;
        sprintf(msg.mtext, username);
        msgsnd(msqid1, &msg, sizeof(msg.mtext), 0);

        //AS错误控制
        msgrcv(msqid1, &msg, 256, 404, 0);
        if(strcmp(msg.mtext,"error")==0){
            printf("Client: receive msg.mtext is: %s.\n", msg.mtext);
            printf("Client: receive msg.mtype is: %ld.\n", msg.mtype);
            printf("-----------------------\n");
            continue;
        }

        //接收消息A
        msgrcv(msqid1, &msg, 256, 'A', 0);
        printf("Client: receive A.mtext is: %s.\n", msg.mtext);
        printf("Client: receive A.mtype is: %ld.\n", msg.mtype);

        char kclient_tgs[8];
        Decrypt(msg.mtext,8,kclient,kclient_tgs);

        //接收消息B
        msgrcv(msqid1, &msg, 256, 'B', 0);
        printf("Client: receive B.mtext is: %s.\n", msg.mtext);
        printf("Client: receive B.mtype is: %ld.\n", msg.mtype);

        char tgt[100];
        sprintf(tgt, msg.mtext);



        //Client 向 TGS 发送以下两条消息

        //发送消息C
        printf("Client: send C\n");
        sprintf(msg.mtext, tgt);
        msg.mtype = 'C';
        msgsnd(msqid2, &msg, sizeof(msg.mtext), 0);

        //发送消息D
        printf("Client: send D\n");
        msg.mtype = 'D';
        unsigned char messaged[100];
        unsigned char plaind[100];
        long timestamp=time(NULL);
        //printf("timestamp:%d\n",timestamp);
        sprintf(plaind,"%ld%s",timestamp,client_id);
        //printf("strlen(plaind):%d\n",strlen(plaind));
        int plainsize=strlen(plaind);
        int ciphersize=Encrypt(plaind, strlen(plaind),kclient_tgs, messaged);
        memcpy(msg.mtext, messaged,ciphersize);
        msg.mtext[ciphersize]='\0';
        //sleep(350);
        msgsnd(msqid2, &msg, sizeof(msg.mtext), 0);

        //TGS错误控制
        msgrcv(msqid2, &msg, 256, 404, 0);
        if(strcmp(msg.mtext,"error")==0){
            printf("Client: receive msg.mtext is: %s.\n", msg.mtext);
            printf("Client: receive msg.mtype is: %ld.\n", msg.mtype);
            printf("-----------------------\n");
            continue;
        }

        //接收消息F
        msgrcv(msqid2, &msg, 256, 'F', 0);
        printf("Client: receive F.mtext is: %s.\n", msg.mtext);
        printf("Client: receive F.mtype is: %ld.\n", msg.mtype);

        char kclient_ss[8];
        Decrypt(msg.mtext,8,kclient_tgs,kclient_ss);

        //接收消息E
        msgrcv(msqid2, &msg, 256, 'E', 0);
        printf("Client: receive E.mtext is: %s.\n", msg.mtext);
        printf("Client: receive E.mtype is: %ld.\n", msg.mtype);

        char st[100];
        sprintf(st, msg.mtext);

        //Client 向 SS 发送以下两条消息
        //发送消息E
        printf("Client: send E\n");
        msg.mtype = 'E';
        sprintf(msg.mtext,st);
        msgsnd(msqid3, &msg, sizeof(msg.mtext), 0);

        //发送消息G
        printf("Client: send G\n");
        msg.mtype = 'G';
        unsigned char messageg[100];
        unsigned char plaing[100];
        timestamp=time(NULL);
        //printf("timestamp:%d\n",timestamp);
        sprintf(plaing,"%ld%s",timestamp,client_id);
        //printf("strlen(plaind):%d\n",strlen(plaing));
        int gciphersize=Encrypt(plaing, strlen(plaing),kclient_ss, messageg);
        memcpy(msg.mtext, messageg,ciphersize);
        msg.mtext[gciphersize]='\0';
        //sleep(350);
        msgsnd(msqid3, &msg, sizeof(msg.mtext), 0);

        //SS错误控制
        msgrcv(msqid3, &msg, 256, 404, 0);
        if(strcmp(msg.mtext,"error")==0){
            printf("Client: receive msg.mtext is: %s.\n", msg.mtext);
            printf("Client: receive msg.mtype is: %ld.\n", msg.mtype);
            printf("-----------------------\n");
            continue;
        }

        //接收消息H
        msgrcv(msqid3, &msg, 256, 'H', 0);
        printf("Client: receive H.mtext is: %s.\n", msg.mtext);
        printf("Client: receive H.mtype is: %ld.\n", msg.mtype);

        unsigned char plainh[100];
        int plainhsize=Decrypt(msg.mtext,strlen(msg.mtext),kclient_ss,plainh);
        plainh[plainhsize]='\0';
        unsigned char newtimestamp[11];
        memcpy(newtimestamp,plainh,10);
        newtimestamp[10]='\0';
        unsigned char client_id_h[50];
        sprintf(client_id_h,"%s",plainh+10);
        long numnewtimestamp=0;
        sscanf(newtimestamp,"%ld",&numnewtimestamp);

        //如果其中的时间戳被正确更新，则 SS 可以信赖，Client 可以向 SS 发送服务请求
        if(numnewtimestamp==timestamp+1){
            printf("Authentication success!!\n");
        }
        else{
            printf("Authentication failed!!\n");
        }

        printf("-----------------------\n");

    }


}
