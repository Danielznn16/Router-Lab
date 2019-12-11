#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include<vector>
#include <string>
#include <sstream>
#include <iostream>
/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/
using namespace std;
vector<RoutingTableEntry> routs;
vector<RoutingTableEntry>* getRoutingTableEntry(){
	return &routs;
}
uint32_t len2_2(uint32_t len){
  uint32_t re = 0;
  for(int i = 0; i < len;i++){
    re = (re << 1)+1;
  }
  return re;
}
/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
	if(insert){
	    int flag = false;
	    for (int i = 0; i < routs.size(); i++)
	    {
	      if ((routs.at(i).addr == entry.addr && routs.at(i).len == entry.len))
	      {
	        routs.at(i).nexthop = entry.nexthop;
	        routs.at(i).if_index = entry.if_index;
	        flag = true;
	        break;
	      }
	    }
	    if(!flag)
	    {
	      routs.push_back(entry);
	    }
  }else{
		for (int i = 0; i < routs.size(); i++){
	      if (routs.at(i).addr == entry.addr && routs.at(i).len == entry.len && routs.at(i).if_index == entry.if_index)
	      {
	        routs.erase(routs.begin() + i);
	        break;
	      }
	    }
	}
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
uint32_t placeholder_metric;
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric = &placeholder_metric) {
		// cout << "addrString: " << addrString << endl;
		int maxlen = -1;
		for(int i = 0; i < routs.size(); i++){
			cout << "routMask: " << len2_2(routs.at(i).len)<< endl;
			if((addr&len2_2(routs.at(i).len)) == (routs.at(i).addr & len2_2(routs.at(i).len))&& maxlen < routs.at(i).len){
				maxlen = routs.at(i).len;
				*nexthop = routs.at(i).nexthop;
				*if_index = routs.at(i).if_index;
				if(metric != NULL)
					*metric = routs.at(i).metric;
			}
		}
	  return (maxlen!=-1);
}
