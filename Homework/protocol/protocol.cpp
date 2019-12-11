#include "rip.h"
#include <stdint.h>
#include <stdlib.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */



bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  
  int data = (((int)packet[2] << 8) + packet[3] - (packet[0] & 0xf) * 4 - 4 ) / 20;
  if(((int)( packet[2] << 8)+ (int)packet[3]>len)||((int)(packet[30] << 8)+(int)packet[31] != 0))return false;
  output->numEntries = 0;
  output->command = packet[28];
  if(!((packet[28] == 0x2 || packet[28] == 0x1) && packet[29] == 0x2))return false;
  for(int i = 0; i < data; i++){
    int data_t = ((int)packet[i*20+32] << 8) + packet[i*20+33];
    int data_met = ((int)packet[i*20+48]<<24)+((int)packet[i*20+49]<<16)+((int)packet[i*20+50]<<8)+packet[i*20+51];
    if(!((packet[28] == 0x2 && data_t == 0x2) || (packet[28] == 0x1 && data_t == 0x0))||(!(data_met <= 16 && data_met >= 1)))return false;
    int data_set = ((int)packet[i*20+40]<<24)+((int)packet[i*20+41]<<16)+((int)packet[i*20+42]<<8)+packet[i*20+43];
    int cur = data_set & 0xf;
    int pre = cur;
    int num = 0;
    for(int i = 1;i < 8;i ++){
        data_set = data_set >> 4;
        cur = data_set & 0xf;
        if(cur != pre){
            num ++;
        }
        pre = cur;
    }
    if(num == 0 || num ==1){
      int set_num = output->numEntries;
      output->entries[set_num].addr = ((int)packet[i*20+39]<<24)+((int)packet[i*20+38]<<16)+((int)packet[i*20+37]<<8)+packet[i*20+36];
      output->entries[set_num].mask = ((int)packet[i*20+43]<<24)+((int)packet[i*20+42]<<16)+((int)packet[i*20+41]<<8)+packet[i*20+40];
      output->entries[set_num].metric = ((int)packet[i*20+51]<<24)+((int)packet[i*20+50]<<16)+((int)packet[i*20+49]<<8)+packet[i*20+48];
      output->entries[set_num].nexthop = ((int)packet[i*20+47]<<24)+((int)packet[i*20+46]<<16)+((int)packet[i*20+45]<<8)+packet[i*20+44];
      output->numEntries++;
    }
    else {
        return false;
    }   
  }
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  buffer[0] = rip->command;
  buffer[1] = 0x2;
  buffer[2] = 0x0;
  buffer[3] = 0x0;
  int num = rip->numEntries;
  
  for(int i = 0;i < num;i ++){
    RipEntry entry = rip->entries[i];
    if (split && dst_addr == entry.nexthop)
    {
      continue;
    }
    buffer[4+i*20] = 0x0;
    if(rip->command == 0x2)buffer[i*20+5] = 0x2;
    else buffer[i*20+5] = 0x0;
    buffer[i*20+6] = 0x0;
    buffer[i*20+7] = 0x0;
    buffer[i*20+8] = rip->entries[i].addr;
    buffer[i*20+9] = rip->entries[i].addr>>8;
    buffer[i*20+10] = rip->entries[i].addr>>16;
    buffer[i*20+11] = rip->entries[i].addr>>24;
    buffer[i*20+12] = rip->entries[i].mask;
    buffer[i*20+13] = rip->entries[i].mask>>8;
    buffer[i*20+14] = rip->entries[i].mask>>16;
    buffer[i*20+15] = rip->entries[i].mask>>24;
    buffer[i*20+16] = rip->entries[i].nexthop;
    buffer[i*20+17] = rip->entries[i].nexthop>>8;
    buffer[i*20+18] = rip->entries[i].nexthop>>16;
    buffer[i*20+19] = rip->entries[i].nexthop>>24;
    buffer[i*20+20] = rip->entries[i].metric;
    buffer[i*20+21] = rip->entries[i].metric>>8;
    buffer[i*20+22] = rip->entries[i].metric>>16;
    buffer[i*20+23] = rip->entries[i].metric>>24;
  }
  return  (rip->numEntries)*20+4;
}
