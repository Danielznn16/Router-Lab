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
            output->numEntries=0;
            output->command=packet[28];
  if(((((int)packet[2])<<8)+packet[3]<=len) //len check
    &&((uint16_t)((int)packet[30]<<8)+packet[31]==0x0000) // check zero
    &&(((uint8_t)packet[28] - 0x01)>>1==0) // check command
    &&(((uint8_t)packet[29])==2) // check version
    ){
      uint8_t cmd = packet[28];
      uint8_t ver = packet[29];
      for(int i = 0; i < (((((int)packet[2])<<8)+packet[3]-(packet[0]&0xf)*4)/24)*20; i+= 20)
        {
          uint16_t af = ((int)packet[32+i]<<8)+packet[33+i];
          uint32_t mtx = ((int)packet[48+i]<<24)+((int)packet[49+i]<<16)+((int)packet[50+i]<<8)+packet[51+i];
          if((!(cmd*2-af == 2)) || mtx < 1 || mtx > 16) // check family and cmd
            return false;
          uint32_t mask = ((int)packet[40+i]<<24)+((int)packet[41+i]<<16)+((int)packet[42+i]<<8)+packet[43+i];
          int tmp = mask%16;//check mask
          short cnt = 0;
          for(int j = 0; j < 7; j++){
            mask = mask>>4;
            if(mask%16 != tmp && cnt++ == 1)
              return false;
            tmp = mask%16;
          }
          int numE = output->numEntries;
          output->entries[numE].addr    =((int)packet[39+i]<<24)+((int)packet[38+i]<<16)+((int)packet[37+i]<<8)+packet[36+i];
          output->entries[numE].mask    =((int)packet[43+i]<<24)+((int)packet[42+i]<<16)+((int)packet[41+i]<<8)+packet[40+i];
          output->entries[numE].nexthop =((int)packet[47+i]<<24)+((int)packet[46+i]<<16)+((int)packet[45+i]<<8)+packet[44+i];
          output->entries[numE].metric  =((int)packet[51+i]<<24)+((int)packet[50+i]<<16)+((int)packet[49+i]<<8)+packet[48+i];
          output->numEntries++;
        }
        return true;
  }
  return false;
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
  uint32_t* tmpBuffer = (uint32_t*)buffer;
  uint16_t* tmpBuffer2 = (uint16_t*)buffer;
  buffer[0]=rip->command;
  buffer[1]=0x2;
  tmpBuffer2[1] = 0x0000;

  for(int i=0;i<rip->numEntries * 5;i+=5){
  RipEntry entry = rip->entries[i/4];
  
  if(rip->command==0x2) 
    tmpBuffer2[2+i*2]=0x0200; 
  else
    tmpBuffer2[2+i*2]=0x0000;
  
  tmpBuffer2[3+i*2]=0x0000;

  tmpBuffer[2+i] = entry.addr;
  tmpBuffer[3+i] = entry.mask;
  tmpBuffer[4+i] = entry.nexthop;
  tmpBuffer[5+i] = entry.metric;
}
  return (rip->numEntries)*20+4;
}
