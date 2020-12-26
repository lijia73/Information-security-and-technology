#pragma once
/*k-密钥
kLen-密钥长度
message-原文
mLen-原文长度
out- 消息摘要
*/
void hmac_md5(unsigned char* k, unsigned int kLen, unsigned char* message, unsigned int mLen, unsigned char* out);