#coding:utf-8
#!/usr/bin/env python  

import sys
import idautils
from idaapi import *
sys.path.append('/Users/maoguai/Desktop/program/py/protocol_reverse/vivisect-master')
import flare.jayutils as c_jayutils
import flare.argtracker as c_argtracker
import logging
logging.basicConfig()

#函数参数个数与push有关
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
	def circle(self, ea, op):
		self.circle_intr = ea
		self.circle_op = op

class Length_Function(object):
	def __init__(self, func, addr, para):
		self.func = func
		self.addr = addr
		self.para = para

#添加封装函数
def fun_package_add(func_name, fun_list):
	for i in fun_list:
		if func_name == i.name :
			i.package(func_name)

#添加疑似函数
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

#深度优先函数路径
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

#读取文件import导入函数
def get_imports(entries):
	for i in range(0,idaapi.get_import_module_qty()):
		dllname = idaapi.get_import_module_name(i)
		def cb(ea, name, ord):
			entries.append(name)
			return True
		idaapi.enum_import_names(i,cb)

def SwapToXiao(c):
	t=32
	return chr(ord(c)+t)

def isJmp(addr):
	SzOp=['JO','JNO','JB','JNB','JE','JNE','JBE','JA','JS','JNS','JP','JNP','JL','JNL','JNG','JG','JCXZ','JECXZ','JMP','JMPE']
	llen=len(SzOp)
	for i in range(0,llen):
		SwapAns = ''
		#把SzOp数组中所有字符串转换成小写字符串
		for c in SzOp[i]:
			SwapAns+=SwapToXiao(c)
		#加到SzOp数组中
		SzOp.append(SwapAns)
	#获取操作指令
	Op=GetMnem(addr)
	#判断是否是操作指令
	if isCode(GetFlags(addr)):
	#判断是否是跳转指令
		for Sin in SzOp:
			if Sin==Op:
				return 1
	return 0

def isCir(func,start,end):
	flag = False
	for ea in range(start,end):
		if isJmp(ea)==1:
			#获取跳转地址
			new_addr=GetDisasm(ea)[-6:]
			#判断是否为挑战地址
			if new_addr[-1:]<='9' and new_addr[-1:]>='0':
				if int(new_addr,16)<ea:
					#添加注释
					#print("循环跳转指令："+ ' '.join(hex(ea)))
					op1 = idc.GetOpnd(ea,0)
					#print("循环起始地址："+ ' '.join(op1))
					func.circle(ea, op1)
					flag = True
					#MakeComm(ea,"循环跳转指令")
	return flag

def isSel(func,start,end):
	flag = False
	cur_start=start
	for cur_start in range(start,end):
		if isJmp(cur_start)==1:
			new_addr=GetDisasm(cur_start)[-6:]
			if new_addr[-1:]<='9' and new_addr[-1:]>='0':
				if int(new_addr,16) > cur_start:
					jmp_addr = idc.GetOpnd(ea,0)
					flag = True

def handleCreateThread(ea):
    vw = c_jayutils.loadWorkspace(c_jayutils.getInputFilepath())
    tracker = c_argtracker.ArgTracker(vw)
    #interestingXrefs = CodeRefsTo(ea, 1)
    #print(interestingXrefs)
    #for xref in interestingXrefs:
    xref = ea
    # 未解决3来源
    argsList = tracker.getPushArgs(xref, 3)#['eax', 'ebx', 'ecx', 'edx', 'edi'])
    #print('argsList:')
    #print (argsList)
    flag = False
    if len(argsList) == 0:
        print('Unable to get push args at: 0x%08x' % xref)
        return flag, None , None
    else:
        for argDict in argsList:
        	#未解决2的来源
            locVa, strloc = argDict[2]
            print 'Found: 0x%08x: 0x%08x' % (locVa, strloc)
            flag = True
            return flag, locVa, strloc

def equal_reg_handle(ea):
	vw = c_jayutils.loadWorkspace(c_jayutils.getInputFilepath())
	tracker = c_argtracker.ArgTracker(vw)
	xref = ea
	op1=idc.GetOpnd(xref,1)
	if op1 == 'eax' or op1 == 'ax' or op1 == 'al':
		m = 'eax'
	elif op1 == 'ebx' or op1 == 'bx' or op1 == 'bl':
		m = 'ebx'
	elif op1 == 'ecx' or op1 == 'cx' or op1 == 'cl':
		m = 'ecx'
	elif op1 == 'edx' or op1 == 'dx' or op1 == 'dl':
		m = 'edx'
	else :
		m = op1
	b = tracker.getPushArgs(xref, 0 ,[m])
	for argDict in b:
		ebxVa, ebxkey = argDict[m]
	print 'Found: 0x%08x: 0x%08x' % (xref, ebxkey)
	vuln_equal_dic[hex(xref)] =hex(ebxkey)

def length_function_recognition(potential_func_list):
	package_func = []
	length_function = []
	for i in potential_func_list:
		if i.is_packaged == True:
			package_func.append(i)
	for func in package_func:
		addr = LocByName(func.name)
		if addr != BADADDR:
			#找到交叉引用的地址
			cross_refs = CodeRefsTo(addr, 0)
			for ref in cross_refs:
				flag, int_addr, int_num = handleCreateThread(ref)
				print flag, int_addr, int_num
				if flag == True:
					a = Length_Function(func, hex(int_addr), int_num)
					length_function.append(a)
	for i in length_function:
		print i.func.name, i.func.origi, i.addr, i.para
	return length_function

def assignment_function_recognition(potential_func_list):
	vuln_equal_array = []
	vuln_equal_dic ={}
	for i in potential_func_list:
		addr = LocByName(func.name)
		call_array = []
		if addr != BADADDR:
			start = addr #GetFunctionAttr(ref, FUNCATTR_START)
			end = GetFunctionAttr(addr, FUNCATTR_END)
			cur_start = start
			while cur_start <= end: ###结束条件为当前指令地址大于函数的结束地址
    		##disasm = idc.GetDisasm(cur_start)
				call_array.append(cur_start)
				cur_start=idc.NextHead(cur_start,end) ###读取下一个指令的地址
			for item in call_array:
				keyInstr = item  #address
				#print hex(keyInstr), idc.GetDisasm(keyInstr)
				if GetMnem(keyInstr) == "mov":
					if GetOpType(keyInstr,1) == 1 :
						equal_reg_handle(keyInstr)
						vuln_equal_array.append(keyInstr)
					elif GetOpType(keyInstr,1) == 5:
						ope_va = GetOperandValue(keyInstr, 1)
						print 'Found: 0x%08x: 0x%08x' % (keyInstr, ope_va)
						vuln_equal_array.append(keyInstr)
						vuln_equal_dic[hex(keyInstr)] = hex(ope_va)

def loop_function_recognition(potential_func_list):
	loop_func =[]
	for func in potential_func_list:
		addr = LocByName(func.name)
		if addr != BADADDR:
			start = addr #GetFunctionAttr(ref, FUNCATTR_START)
			end = GetFunctionAttr(addr, FUNCATTR_END)
			if isCir(func, start, end) :
				loop_func.append(func)

def selection_function_recognition(potential_func_list):
	for func in potential_func_list:
		addr = LocByName(func.name)
		if addr != BADADDR:
			start = addr #GetFunctionAttr(ref, FUNCATTR_START)
			end = GetFunctionAttr(addr, FUNCATTR_END)
			if isSel(func, start, end):
				print "1"

#特征识别

def feature_recognition(potential_func_list):
	length_function = length_function_recognition(potential_func_list)
	'''
	assignment_function_recognition(potential_func_list)
	loop_function_recognition(potential_func_list)
	selection_function_recognition(potential_func_list)
	'''

#筛选疑似函数
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
	old = []
	new = []
	#存放反向调用链信息
	recv_recall_chain = []
	for func in potential_func :
		del recv_recall_chain[:]
		get_caller(func, osintneting, potential_func_list, recv_recall_chain)
	#获取封装函数
	osintneting = 2
	for func in potential_func :
		del recv_recall_chain[:]
		old = package_func[:]
		get_caller(func, osintneting, package_func, recv_recall_chain)
		new = list(set(package_func).difference(set(old)))
		if new:
			for i in new:
				for j in potential_func_list:
					if i.name == j.name:
						j.package(func)
	return potential_func_list

#main
def main():
	potential_func_list = filter_potential_func()
	feature_recognition(potential_func_list)
	'''
	print 'i'
	if length_function_list:
		for i in length_function_list:
			if i.is_length == True:
				print i.name, i.origi, i.len_func_addr, i.len_func_para
	'''

if __name__=="__main__":
	main()