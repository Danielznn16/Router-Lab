#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <iostream>
using namespace std;
extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer, bool split, uint32_t dst_addr);
extern vector<RoutingTableEntry> getRoutingTableEntry();
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric);
void printRoutingTableEntry(RoutingTableEntry tmp){
  cout << "addr:" << 
    ((tmp.addr & 0xff000000) >> 24) << "." << 
    ((tmp.addr & 0x00ff0000) >> 16) << "." << 
    ((tmp.addr & 0x0000ff00) >> 8) << "." << 
    (tmp.addr & 0x000000ff) << 
    "\tnexthop:" << 
    tmp.nexthop << "\tlen:" << 
    tmp.len << "\tmetric:" << 
    tmp.metric << "\tif_Index:" << 
    tmp.if_index << endl;
}
uint8_t packet[2048];
uint8_t output[2048];
uint16_t* output16 = (uint16_t*)output;
uint32_t* outputAddr = (uint32_t*)output;
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
// in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a, 0x0103000a};
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a, 0x0103000a};
in_addr_t multicast_address = 0x090000e0;
macaddr_t multicast_mac_addr = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x16}; // multicasting mac address 01:00:5e:00:00:09

uint32_t len2(uint32_t len){
  uint32_t re = 0;
  for(int i = 0; i < len;i++){
    re = (re << 1)+1;
  }
  return re;
}

uint32_t reverseLen(uint32_t len){
  uint32_t re = 0;
  while(len > 0){
    re++;
    // len = len>>1;
  }
  return re;
}

uint32_t convertEndian(uint32_t tmp){
  uint8_t* re = (uint8_t*)(&tmp);
  swap(re[0],re[3]);
  swap(re[1],re[2]);
  return *((uint32_t*)re);
}

uint16_t getChecksum(uint8_t *packet,int leng) {
  // TODO:
  unsigned long long check = 0;
  for(unsigned long long tmp = 0; tmp < leng; tmp++){
    check += (((leng-1) - tmp)%2 == 0)?packet[tmp]:(((int)packet[tmp])<<8);
  }
  while((check > (1<<16)))
    check = (check>>16) + (check&0xffff);
  unsigned short re = ~check;
  return re;
}

void updateRipPacket(RipPacket* ripPack){
  std::vector<RoutingTableEntry> table = getRoutingTableEntry();
  ripPack->numEntries = table.size();
  ripPack->command = 2;
  for(int i = 0; i < ripPack->numEntries; i++){
    RipEntry ripE;
    ripE.mask = __builtin_bswap32 (convertEndian(len2(table.at(i).len)));
    ripE.addr = table.at(i).addr & ripE.mask;
    ripE.metric = __builtin_bswap32 (uint32_t(table.at(i).metric));
    ripE.nexthop = table.at(i).nexthop;
    ripPack->entries[i] = ripE;
    }
}

uint32_t sendIPPacket(RipPacket* ripPackedge, in_addr_t src_addr, in_addr_t dst_addr, bool split){
      output[0] = 0x45;
      // Differentiated Service Field
      output[1] = 0x00;
      // Id
      output16[2] = 0x0000;
      // Flags
      output16[3] = 0x0000;
      // TTL & protocol
      output16[4] = 0x1101;
      //checksum
      output16[5] = 0x0000;
      output16[13] = 0x0000;
      // UDP
      // port = 520
      output16[10] = 0x0802;
      output16[11] = 0x0802;
      outputAddr[4] = multicast_address;
      outputAddr[3] = src_addr;
      uint32_t rip_len = assemble(ripPackedge, &output[20 + 8], split, dst_addr);
      output[2] = (rip_len+28)>>8;
      output[3] = (rip_len+28);
      // cout << "rip_len\t" << rip_len + 28 << endl;
      output[24] = (rip_len+8)>>8;
      output[25] = (rip_len+8);
      // cout << "rip_len-2\t" << rip_len + 8 << endl;

      output16[5] = getChecksum(output, 20);
      return rip_len;
}

int main(int argc, char *argv[]) {
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }
  
  // Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD;i++) {
    RoutingTableEntry entry = {
      .addr = addrs[i], // big endian
      .len = 24, // small endian
      .if_index = i, // small endian
      .nexthop = 0, // big endian, means direct
      .metric = 1
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // cnt time and send rip routing table periodically
      printf("Timer\n");
      for(int i=0; i<N_IFACE_ON_BOARD; i++) {
        RipPacket ripPack;
        updateRipPacket(&ripPack);
        HAL_SendIPPacket(i, output, sendIPPacket(&ripPack, addrs[i], multicast_address, false) + 20 + 8, multicast_mac_addr);
      }
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                                  dst_mac, 1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    memcpy(&dst_addr, &packet[16], sizeof(in_addr_t));
    memcpy(&src_addr, &packet[12], sizeof(in_addr_t));
    // src_addr = convertEndian(src_addr);
    // dst_addr = convertEndian(dst_addr);
    cout << "\n" << 
    ((dst_addr & 0xff000000) >> 24) << "." << 
    ((dst_addr & 0x00ff0000) >> 16) << "." << 
    ((dst_addr & 0x0000ff00) >> 8) << "." << 
    (dst_addr & 0x000000ff)  << endl;
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    if (memcmp(&dst_addr, &multicast_address, sizeof(in_addr_t)) == 0)
    {
      dst_is_me = true;
    }
    // TODO: Handle rip multicast address?
    if (dst_is_me) {
      // TODO: RIP?
      RipPacket rip;
      cout << "reached is me\n";  
      if (disassemble(packet, res, &rip)) {
        // cout << "reached1\n";
        if (rip.command == 1) {
          // request
          RipPacket resp;
          updateRipPacket(&resp);
          // ...
          // RIP
          uint32_t rip_len = sendIPPacket(&resp, src_addr, dst_addr, true);
          HAL_SendIPPacket(if_index, output, rip_len + 28, src_mac);
        } else {
          // response
          // TODO: use query and updatec
          std::vector<RoutingTableEntry> failers;
          cout << "response reached with rip length" << rip.numEntries << endl;
          for(int j = 0; j < rip.numEntries; j++){
            RoutingTableEntry etr;
            etr.addr = rip.entries[j].addr;
            etr.nexthop = rip.entries[j].nexthop;
            etr.len = reverseLen(convertEndian(rip.entries[j].mask));
            etr.metric = rip.entries[j].metric + 1;
            etr.if_index = if_index;
            cout << "debug";
            printRoutingTableEntry(etr);
            if(rip.entries[j].metric + 1 > 16){
              //delete route
              update(false,etr);
              failers.push_back(etr);
            } else {
              uint32_t search_if_index,search_nexthop,search_metric;
              if(query(etr.addr, &search_nexthop, &search_if_index, &search_metric)){
                if(etr.metric <= search_metric){
                  update(true,etr);
                }
              }else{
                update(true,etr);
              }

              //print rout
              cout << "updated";
              printRoutingTableEntry(etr);

            }
          }

          //fails
          RipPacket fails;
          fails.numEntries = failers.size();
          for(int i = 0; i < failers.size();i++){
            RipEntry etr;
            etr.addr = failers[i].addr;
            etr.nexthop = failers[i].nexthop;
            etr.mask = convertEndian(len2(failers[i].len));
            etr.metric = convertEndian((uint32_t)1);
            fails.entries[i] = etr;
          }

          //routing table
          RipPacket routs;
          std::vector<RoutingTableEntry> routingTableEntry = getRoutingTableEntry();
          routs.numEntries = routingTableEntry.size();
          for(int i = 0; i < routingTableEntry.size();i++){
            RipEntry etr;
            etr.addr = routingTableEntry[i].addr;
            etr.nexthop = routingTableEntry[i].nexthop;
            etr.mask = convertEndian(len2(routingTableEntry[i].len));
            etr.metric = convertEndian((uint32_t)1);
            routs.entries[i] = etr;
          }

          //assign


          output[0] = 0x45;
          output[1] = 0x00;

          output[4] = 0x00;
          output[5] = 0x00;
          output[6] = 0x00;
          output[7] = 0x00;

          output[8] = 0x01;
          output[9] = 0x11;
          output[20] = 0x02;
          output[21] = 0x08;

          output[22] = 0x02;
          output[23] = 0x08;
          uint32_t* outputAddr = (uint32_t*)output;
          outputAddr[3] = dst_addr;

          uint16_t* output16 = (uint16_t*)output;

          //send failures
          if(!failers.empty())
            for(int i = 0; i < N_IFACE_ON_BOARD; i++){
              if(i!= if_index){
                outputAddr[4] = addrs[i];
                output16[5] = 0x0000;
                uint32_t rip_len = assemble(&fails, &output[20 + 8], false, 0);
                output16[1] = rip_len + 28;//total length
                output16[5] = getChecksum(output,20);
                output16[12] = rip_len + 8;//UDP length
                output16[13] = 0;
                {
                  uint32_t tmp2 = addrs[i] + dst_addr + (17<<16) + rip_len+8 + outputAddr[10] + outputAddr[11];
                  tmp2 = (tmp2>>16) + (tmp2&0xffff);
                  output16[13] = (unsigned short)(~tmp2);
                }
                HAL_SendIPPacket(i, output, rip_len + 20 + 8, src_mac);
              }
            }

          //send Routing

          {
            output[0] = 0x45;
            output[1] = 0x00;

            output[4] = 0x00;
            output[5] = 0x00;
            output[6] = 0x00;
            output[7] = 0x00;

            output[8] = 0x01;
            output[9] = 0x11;
            output[20] = 0x02;
            output[21] = 0x08;

            output[22] = 0x02;
            output[23] = 0x08;
            uint32_t* outputAddr = (uint32_t*)output;
            outputAddr[3] = dst_addr;

            uint16_t* output16 = (uint16_t*)output;

            //send failures
            for(int i = 0; i < N_IFACE_ON_BOARD; i++){
              outputAddr[4] = addrs[i];
              output16[5] = 0x0000;
              uint32_t rip_len = assemble(&routs, &output[20 + 8],false, 0);
              output16[1] = rip_len + 28;//total length
              output16[5] = getChecksum(output,20);
              output16[12] = rip_len + 8;//UDP length
              output16[13] = 0;
              {
                uint32_t tmp2 = addrs[i] + dst_addr + (17<<16) + rip_len+8 + outputAddr[10] + outputAddr[11];
                tmp2 = (tmp2>>16) + (tmp2&0xffff);
                output16[13] = (unsigned short)(~tmp2);
              }
              HAL_SendIPPacket(i, output, rip_len + 20 + 8, src_mac);
            }
            //TODO: print
          }
        }
      } else {
        // forward
        // beware of endianness
        uint32_t nexthop, dest_if, b3_metric;
        if (query(src_addr, &nexthop, &dest_if, &b3_metric)) {
          // found
          macaddr_t dest_mac;
          // direct routing
          if (nexthop == 0) {
            nexthop = dst_addr;
          }
          if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
            // found
            memcpy(output, packet, res);
            // update ttl and checksum
            forward(output, res);
            // TODO: you might want to check ttl=0 case
            if(output[8] == 0x00){
              output[0] = 0x0b;
              output[1] = 0x00;

              // ICMP checksum
              output16[1] = 0x0000;

              outputAddr[1] = 0x00000000;

              // assign IP's head with 64bit data
              for (int i=0; i<28; i++) {
                output[i+8] = packet[i];
              }

              unsigned short sum = getChecksum(output, 36);
              output16[1] = sum;
              HAL_SendIPPacket(if_index, output, 36, dest_mac);
            }
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          } else {
            // not found
            printf("mac address unfound for dst_if:\t%u nexthop:\t%u dst_mac:\t%u\n", src_addr,nexthop,dest_if);
          }
        } else {
          // not found
        }
      }
    }
  }
  return 0;
}
