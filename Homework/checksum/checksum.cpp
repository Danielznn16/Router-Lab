#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
// bool validateIPChecksum(uint8_t *packet, size_t len) {
//   // TODO:
// 	unsigned long long check = 0;
// 	int leng = (int)(packet[0]&0xf)*4;
// 	for(unsigned long long tmp = 0; tmp < leng; tmp++){
// 		check += (((leng-1) - tmp)%2 == 0)?packet[tmp]:(((int)packet[tmp])<<8);
// 	}
// 	while((check > (1<<16)))
// 		check = (check>>16) + (check&0xffff);
//     unsigned short re = ~check;
//   return re==0x0000;
	// size_t nleft = len;
 //    uint32_t sum = 0;
 //    uint16_t *w=(uint16_t *)packet;
 //    uint16_t answer = 0;
 //    while(nleft > 1){    // 16bit为单位累加运算
 //        sum += *(w++);
 //        nleft -= 2;
 //    }   
 //    if(nleft == 1){  //若addr奇数个字节,会剩下最后一字节.
 //       sum += *( uint8_t*)w;  
 //    }   
 //    sum = (sum>>16) + (sum&0xffff);
 //    sum += (sum>>16);
 //    answer = ~sum;
 //    return answer;
}
