#coding:utf-8
#!/usr/bin/env python  

import sys
import idautils
from idaapi import *
sys.path.append('vivisect')
import logging
logging.basicConfig()

class Functions(object):
	def __init__(self,name):
		self.name = name
		self.num =1
		self.is_packaged = False
		#self.origi = None
	def increase_num(self):
		self.num += 1
	def package(self, origi):
		self.is_packaged = True
		self.origi = origi

def fun_package_add(func_name, fun_list):
	for i in fun_list:
		if func_name == i.name :
			i.package(func_name)

def fun_list_add(func_name, fun_list):
	flag = False
	for i in fun_list:
		if func_name == i.name :
			i.increase_num()
			flag = True
			break
	if flag == False:
		a = Functions(func_name)
		fun_list.append(a)

def get_caller(func_name, osintneting, fun_list, recv_recall_chain):
	str = '{0}\t'.format(func_name)
	recv_recall_chain.append(str)
	addr = get_name_ea(0, func_name)
	addr_ref_to = get_first_fcref_to(addr)
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
			fun_list_add(recv_recall_chain[length - idx - 1], fun_list)
			#sys.stdout.write(recv_recall_chain[length - idx - 1])
		#sys.stdout.write('\r\n')
		recv_recall_chain.pop()
		return
	# 深度优先
	while (addr_ref_to != BADADDR) and (addr_ref_to != addr):
		parent_func_name = get_func_name(addr_ref_to)
		get_caller(parent_func_name, osintneting - 1, fun_list, recv_recall_chain)
		addr_ref_to = get_next_fcref_to(addr, addr_ref_to)
		if addr_ref_to == BADADDR:
			recv_recall_chain.pop() # 如果没有引用函数，弹出当前函数
			break

def get_imports(entries):
	for i in range(0,idaapi.get_import_module_qty()):
		dllname = idaapi.get_import_module_name(i)
		def cb(ea, name, ord):
			entries.append(name)
			return True
		idaapi.enum_import_names(i,cb)

def filter_potential_func():
	entries = []
	potential_func = []
	get_imports(entries)
	#通信函数，WS2_32.dll中的TCP，UDP通信函数
	socket_func = ['send', 'recv', 'sendto', 'recvfrom']
	for func in  socket_func:
		if func in entries:
			potential_func.append(func)
	#其他通信函数
	#未实现
	#add_socket_func(potential_func)
	osintneting = 5
	potential_func_list = []
	package_func = []
	#存放反向调用链信息
	recv_recall_chain = []
	for func in potential_func :
		del recv_recall_chain[:]
		get_caller(func, osintneting, potential_func_list, recv_recall_chain)
	#获取封装函数
	osintneting = 2
	for func in potential_func :
		del recv_recall_chain[:]
		get_caller(func, osintneting, package_func, recv_recall_chain)
		for i in package_func:
			for j in potential_func_list:
				if i.name == j.name:
					j.package(func)
	return potential_func_list
#main
def main():
	potential_func_list = filter_potential_func()
	for i in potential_func_list:
		if i.is_packaged == False:
			print i.name, i.num
		else:
			print i.name,i.is_packaged,i.origi

if __name__=="__main__":
	main()