#coding:utf-8
#!/usr/bin/env python  
'''
class Functions(object):
	def __init__(self,name):
		self.name = name
	start_addr
	end_addr
	exist_Loop
	exist_Equal
	exist_switch
'''

import idb
import sys
sys.path.append('vivisect')
import logging
logging.basicConfig()



def get_caller(api, func_name, osintneting, fun_list, recv_recall_chain):
	del recv_recall_chain[:]
	str = '{0}\t'.format(func_name)
	recv_recall_chain.append(str)
	print dir(api.idaapi.idb)
	'''
	addr = api.idaapi.get_name_ea(0, func_name)
	addr_ref_to = api.idc.get_first_fcref_to(addr)
	#嵌套结束条件 
	osinteneting_end = False
	if addr_ref_to == BADADDR:
		osinteneting_end = True
	elif osintneting == -1:
		osinteneting_end = False
	elif osintneting == 1:
		osinteneting_end = True
	if osinteneting_end is True:
		length = len(recv_recall_chain)
		for idx in range(length):
			sys.stdout.write(recv_recall_chain[length - idx - 1])
		sys.stdout.write('\r\n')
		recv_recall_chain.pop()
		return

	# 深度优先
	while (addr_ref_to != BADADDR) and (addr_ref_to != addr):
		parent_func_name = get_func_name(addr_ref_to)
		get_caller(parent_func_name, osintneting - 1, fl)
		addr_ref_to = get_next_fcref_to(addr, addr_ref_to)
		if addr_ref_to == BADADDR:
			recv_recall_chain.pop() # 如果没有引用函数，弹出当前函数
			break
	'''
def filter_potential_fuc(api):
	#通信函数，WS2_32.dll中的TCP，UDP通信函数
	socket_tcp_func = ['send', 'recv', 'sendto', 'recvfrom']
	#其他通信函数
	#未实现
	#add_socket_func(socket_func)
	fun_list = []
	#存放反向调用链信息
	recv_recall_chain = []
	get_caller(api,'send', 5, fun_list, recv_recall_chain)


#输入
def read_idb_file():
	file_path = "database/PacsAnalyzer.idb"
	with idb.from_file(file_path) as db:
		api = idb.IDAPython(db)
	return api

#main
def main():
	api = read_idb_file()
	filter_potential_fuc(api)
	'''
	i = 0 
	for ea in api.idautils.Functions():
		i = i + 1
		x = api.idc.GetMnem(ea)
	print x
	print "there are %s functions in file"%i
	'''

if __name__=="__main__":
	main()