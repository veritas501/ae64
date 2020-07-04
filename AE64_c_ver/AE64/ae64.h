#pragma once
#include "bytes.h"
#include <cstring>
#include <iostream>
#include <keystone.h>
#include <map>
#include <vector>

using namespace std;

typedef unsigned char uchar;

// Disable enum class warning
#pragma warning(disable: 26812)

enum x64Register {
	RAX,
	RBX,
	RCX,
	RDX,
	RDI,
	RSI,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,
	RBP,
	RSP,
	UNK_REG
};

struct MulCacheStruc {
	unsigned short word;
	unsigned char byte;
};

struct MulGadgetStruc {
	MulCacheStruc mul;
	unsigned char offset;
};

struct EncodeInfoStruc {
	unsigned short idx;
	x64Register reg;
	bool useLowByte;
};

struct EncodeInfoPlusStruc {
	EncodeInfoStruc info;
	MulGadgetStruc gadget;
	bool needPushByte;
	bool needChangeRdi;
	bool needChangeRdx;
	bool needRecoverRdx;
};

static map<x64Register, const char*> x64RegisterStr = {
	{RAX,"rax"},
	{RBX,"rbx"},
	{RCX,"rcx"},
	{RDX,"rdx"},
	{RDI,"rdi"},
	{RSI,"rsi"},
	{ R8, "r8"},
	{ R9, "r9"},
	{R10,"r10"},
	{R11,"r11"},
	{R12,"r12"},
	{R13,"r13"},
	{R14,"r14"},
	{R15,"r15"},
	{RBP,"rbp"},
	{RSP,"rsp"}
};

class AE64 {
private:
	// keystone
	ks_engine* ks = nullptr;
	ks_err err = KS_ERR_OK;

	// charset
	const char* charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	size_t charsetLength = strlen(charset);


	// cache£¬key == struc.word * struc.byte
	map<unsigned short, MulCacheStruc> mulCache;
	unsigned short preMulResult = 0;

	// asm snippets
	bytes nop;
	bytes nop2;
	bytes initDecoder;
	bytes clearRdi;

	// private funtion
	void InitSnippets();
	bytes GenPrologue(x64Register reg);
	string StrBuilder(const char* fmt, ...);
	bytes GenEncodedShellcode(bytes sc, vector<EncodeInfoStruc>& encodeInfo);
	bytes GenDecoder(vector<EncodeInfoStruc> encodeInfo, unsigned short offset);
	int OptimizeEncodeInfo(vector<EncodeInfoPlusStruc>& encodeInfoPlus, vector<EncodeInfoStruc> encodeInfo, unsigned short offset);
	bool InOffsetRange(int num);

public:
	// ctor and dtor
	AE64(ks_err& error);
	~AE64();

	// export function
	const char* Encode(const unsigned char* sc, size_t length, x64Register addrRegister, size_t offset = 0);
	bytes GenMachineCode(string asmCode);
};