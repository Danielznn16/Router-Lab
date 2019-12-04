#include <stdint.h>
#include <stdlib.h>

bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
	unsigned long long check = 0;
	int leng = (int)(packet[0]&0xf)*4;
	for(unsigned long long tmp = 0; tmp < leng; tmp++){
		check += (((leng-1) - tmp)%2 == 0)?packet[tmp]:(((int)packet[tmp])<<8);
	}
	while((check > (1<<16)))
		check = (check>>16) + (check&0xffff);
    unsigned short re = ~check;
  return re==0x0000;
}
/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  // TODO:
	bool re = validateIPChecksum(packet,len);
	if(re){
		packet[8]--;
		packet[10] = 0;
		packet[11] = 0;
		unsigned long long check = 0;
		int leng = (int)(packet[0]&0xf)*4;
		for(unsigned long long tmp = 0; tmp < leng; tmp++){
			check += (((leng-1) - tmp)%2 == 0)?packet[tmp]:(((int)packet[tmp])<<8);
		}
		while((check > (1<<16)))
			check = (check>>16) + (check&0xffff);
	    unsigned short newSum = ~check;
	    packet[10] = newSum>>8;
	    packet[11] = newSum;
	}
  return re;
}