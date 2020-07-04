#include "ae64.h"
#include <cstdarg>
#include <iomanip>
#include <ctime>

//////////////////////     ctor and dtor    //////////////////////

/*
	If error != KS_ERR_OK, then initialize failed.
*/
AE64::AE64(ks_err& error) {
	error = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
	InitSnippets();
	mulCache.clear();
}

AE64::~AE64() {
	if (ks) {
		ks_close(ks);
	}
}

//////////////////////     private functions    //////////////////////

// initialize some useful asm snippets
void AE64::InitSnippets() {
	const char* initDecoderAsm = R"rawStr(
		/* set encoder */
		/* 0x6d57 x 0x33 == 0xc855 (200,85) rdx */
		/* 0x424a x 0x38 == 0x8030 (128,53) r8 */
		/* 0x436b x 0x4b == 0xc059 (192,89) r9 */
		/* 0x6933 x 0x43 == 0x8859 (136,89) r10 */
		
		push   0x33
		push   rsp
		pop    rcx
		imul   di,WORD PTR [rcx],0x6d57
		push   rdi
		pop    rdx /* 0xc855 */

		push   0x38
		push   rsp
		pop    rcx
		imul   di,WORD PTR [rcx],0x424a
		push   rdi
		pop    r8 /* 0x8030 */

		push   0x4b
		push   rsp
		pop    rcx
		imul   di,WORD PTR [rcx],0x436b
		push   rdi
		pop    r9 /* 0xc059 */

		push   0x43
		push   rsp
		pop    rcx
		imul   di,WORD PTR [rcx],0x6933
		push   rdi
		pop    r10 /* 0x8859 */
		;)rawStr";
	const char* clearRdiAsm = R"rawStr(
		push rdi
		push rsp
		pop rcx
		xor rdi,[rcx]
		pop rcx
		;)rawStr";
	const char* nopAsm = "push rcx;";
	const char* nop2Asm = "push rcx;pop rcx;";

	if (!ks) {
		cerr << "[-] keystone engine not initialized" << endl;
		return;
	}

	initDecoder = GenMachineCode(initDecoderAsm);
	if (!initDecoder.length()) {
		cerr << "[-] Failed on get initDecoder's machine code, error code = " << ks_errno(ks) << endl;
	}
	clearRdi = GenMachineCode(clearRdiAsm);
	if (!clearRdi.length()) {
		cerr << "[-] Failed on get clearRdi's machine code, error code = " << ks_errno(ks) << endl;
	}
	nop = GenMachineCode(nopAsm);
	if (!nop.length()) {
		cerr << "[-] Failed on get nop's machine code, error code = " << ks_errno(ks) << endl;
	}
	nop2 = GenMachineCode(nop2Asm);
	if (!nop2.length()) {
		cerr << "[-] Failed on get nop2's machine code, error code = " << ks_errno(ks) << endl;
	}
}

bytes AE64::GenPrologue(x64Register reg) {
	bytes res;
	if (reg != RAX) {
		res += GenMachineCode(StrBuilder("push %s;pop rax", x64RegisterStr[reg]));
	}
	res += clearRdi + initDecoder;
	return res;
}

bytes AE64::GenEncodedShellcode(bytes sc, vector<EncodeInfoStruc>& encodeInfo) {
	// well-designed value to fit any condition
	x64Register regs[] = { RDX, R8, R9, R10 };
	uchar lBytes[] = { 0x55, 0x30, 0x59, 0x59 };
	uchar hBytes[] = { 0xc8, 0x80, 0xc0, 0x88 };
	EncodeInfoStruc tmpInfo;
	bytes res = sc;
	size_t len;

	encodeInfo.clear();
	len = sc.length();
	for (unsigned short i = 0; i < len; ++i) {
		if (isalnum(sc[i])) {
			continue;
		}
		tmpInfo.idx = i;
		if (sc[i] < 0x80) {
			//use dl to do xor
			tmpInfo.useLowByte = true;
			for (size_t j = 0; j < 4; ++j) {
				if (isalnum(lBytes[j] ^ sc[i])) {
					tmpInfo.reg = regs[j];
					res[i] ^= lBytes[j];
					break;
				}
			}
		}
		else {
			//use dh to do xor
			tmpInfo.useLowByte = false;
			for (size_t j = 0; j < 4; ++j) {
				if (isalnum(hBytes[j] ^ sc[i])) {
					tmpInfo.reg = regs[j];
					res[i] ^= hBytes[j];
					break;
				}
			}
		}
		encodeInfo.push_back(tmpInfo);
	}

	return res;
}

bool AE64::InOffsetRange(int num) {
	if (('0' <= num && num <= '9') ||
		('A' <= num && num <= 'Z') ||
		('a' <= num && num <= 'z')) {
		return true;
	}
	return false;
}

int AE64::OptimizeEncodeInfo(vector<EncodeInfoPlusStruc>& encodeInfoPlus, vector<EncodeInfoStruc> encodeInfo, unsigned short offset) {
	size_t count = encodeInfo.size();
	size_t lastUpdate = 0;
	int* book = new int[count];
	memset(book, 0, count * sizeof(int));

	unsigned short cacheRdi = 0;
	unsigned char cacheStackByte = 0;

	vector<EncodeInfoPlusStruc> useRdx;
	vector<EncodeInfoPlusStruc> useR8;
	vector<EncodeInfoPlusStruc> useR9;
	vector<EncodeInfoPlusStruc> useR10;

	EncodeInfoPlusStruc tmpInfo;
	MulGadgetStruc mulGadget;

	bool noUpdate;
	bool needCalcNewRdi;
	bool needChangeRdi;
	bool needPushByte;

	while (true) {
		noUpdate = true;
		needCalcNewRdi = true;
		needChangeRdi = true;
		needPushByte = false;
		for (size_t i = lastUpdate; i < count; i++) {
			if (book[i]) {
				continue;
			}
			if (needCalcNewRdi) {
				needCalcNewRdi = false;
				lastUpdate = i;
				unsigned short target = encodeInfo[i].idx + offset;
				for (size_t offIdx = 0; offIdx < charsetLength; ++offIdx) {
					unsigned short mulWord;
					unsigned char mulByte;
					unsigned short ans;
					size_t highByte,lowByte,b;
					// optimize 1. use old stack byte
					if (cacheStackByte) {
						for (highByte = 0; highByte < charsetLength; ++highByte) {
							for (lowByte = 0; lowByte < charsetLength; ++lowByte) {
								mulWord = (charset[highByte] << 8) + charset[lowByte];
								ans = (mulWord * cacheStackByte) & 0xffff;
								if (ans + charset[offIdx] == target) {
									cacheRdi = ans;
									needPushByte = false;
									goto save_result;
								}
							}
						}
					}
					// can't use old stack byte
					for (highByte = 0; highByte < charsetLength; ++highByte) {
						for (lowByte = 0; lowByte < charsetLength; ++lowByte) {
							mulWord = (charset[highByte] << 8) + charset[lowByte];
							for (b = 0; b < charsetLength; ++b) {
								mulByte = charset[b];
								ans = (mulWord * mulByte) & 0xffff;
								if (ans + charset[offIdx] == target) {
									cacheRdi = ans;
									cacheStackByte = mulByte;
									needPushByte = true;
								save_result:
									mulGadget.mul.byte = cacheStackByte;
									mulGadget.mul.word = mulWord;
									mulGadget.offset = target - ans;
									tmpInfo.needPushByte = false;
									tmpInfo.needChangeRdi = false;
									tmpInfo.gadget = mulGadget;
									goto break1;
								}
							}
						}
					}
				}
				cerr << "[-] can't find mul gadget, this should not happen" << endl;
				return 1;
			}
		break1:
			// optimize 2. try to use old rdi
			if (InOffsetRange(encodeInfo[i].idx + offset - cacheRdi)) {
				noUpdate = false;
				book[i] = 1;
				// optimize 3. try to use old rdx
				tmpInfo.info = encodeInfo[i];
				tmpInfo.needChangeRdx = false;
				tmpInfo.needRecoverRdx = false;
				tmpInfo.gadget.offset = encodeInfo[i].idx + offset - cacheRdi;
				switch (encodeInfo[i].reg) {
				case RDX:
					useRdx.push_back(tmpInfo);
					break;
				case R8:
					useR8.push_back(tmpInfo);
					break;
				case R9:
					useR9.push_back(tmpInfo);
					break;
				case R10:
					useR10.push_back(tmpInfo);
					break;
				}
			}
		}// for end
		if (useRdx.size() > 0) {
			useRdx[0].needChangeRdx = true;
			useRdx[useRdx.size() - 1].needRecoverRdx = true;
		}
		if (useR8.size() > 0) {
			useR8[0].needChangeRdx = true;
			useR8[useR8.size() - 1].needRecoverRdx = true;
		}
		if (useR9.size() > 0) {
			useR9[0].needChangeRdx = true;
			useR9[useR9.size() - 1].needRecoverRdx = true;
		}
		if (useR10.size() > 0) {
			useR10[0].needChangeRdx = true;
			useR10[useR10.size() - 1].needRecoverRdx = true;
		}
		useRdx.insert(useRdx.end(),useR8.begin(),useR8.end());
		useRdx.insert(useRdx.end(), useR9.begin(), useR9.end());
		useRdx.insert(useRdx.end(), useR10.begin(), useR10.end());
		useRdx[0].needChangeRdi = needChangeRdi;
		useRdx[0].needPushByte = needPushByte;
		encodeInfoPlus.insert(encodeInfoPlus.end(), useRdx.begin(), useRdx.end());
		useRdx.clear();
		useR8.clear();
		useR9.clear();
		useR10.clear();
		if (noUpdate) {
			break;
		}
	}

	delete[] book;
	return 0;
}

bytes AE64::GenDecoder(vector<EncodeInfoStruc> encodeInfo, unsigned short offset) {
	string decoderAsm = "";
	bytes res;
	vector<EncodeInfoPlusStruc> encodeInfoPlus;

	OptimizeEncodeInfo(encodeInfoPlus, encodeInfo, offset);

	size_t count = encodeInfoPlus.size();
	for (size_t i = 0; i < count; i++) {
		if (encodeInfoPlus[i].needChangeRdi) {
			if (encodeInfoPlus[i].needPushByte) {
				decoderAsm += StrBuilder(
					"push %d;push rsp;pop rcx;",
					encodeInfoPlus[i].gadget.mul.byte);
			}
			decoderAsm += StrBuilder(
				"imul di,[rcx],%d;\n",
				encodeInfoPlus[i].gadget.mul.word);
		}
		if (encodeInfoPlus[i].info.reg != RDX 
		&& encodeInfoPlus[i].needChangeRdx) {
			decoderAsm += StrBuilder(
				"push rdx;push %s;pop rdx;\n",
				x64RegisterStr[encodeInfoPlus[i].info.reg]);
		}
		if (encodeInfoPlus[i].info.useLowByte) {
			decoderAsm += StrBuilder(
				"xor [rax+rdi+%d],dl;\n",
				encodeInfoPlus[i].gadget.offset);
		}
		else {
			decoderAsm += StrBuilder(
				"xor [rax+rdi+%d],dh;\n",
				encodeInfoPlus[i].gadget.offset);
		}
		if (encodeInfoPlus[i].info.reg != RDX
		&& encodeInfoPlus[i].needRecoverRdx) {
			decoderAsm += "pop rdx;\n";
		}

	}
	res = GenMachineCode(decoderAsm);
	return res;
}

bytes AE64::GenMachineCode(string asmCode) {
	uchar* machineCode = nullptr;
	size_t size;
	bytes res;
	size_t count = 0;
	if (ks_asm(ks, asmCode.c_str(), 0, &machineCode, &size, &count)) {
		cerr << "[-] Failed on ks_asm() with error code = " << ks_errno(ks) << endl;
		return bytes();
	}
	res = bytes(machineCode, size);
	ks_free(machineCode);
	return res;
}

string AE64::StrBuilder(const char* fmt, ...) {
	int len;
	string str;
	va_list args;
	char buffer[0x1000];
	va_start(args, fmt);
	if ((len = vsnprintf(buffer, sizeof(buffer), fmt, args)) > 0) {
		if (len < sizeof(buffer)) {
			str = buffer;
		}
		else {
			int maxsz = len + 1;
			char* buffer = new char[maxsz];
			if (buffer) {
				len = vsnprintf(buffer, maxsz, fmt, args);
				if (len > 0 && len < maxsz) {
					str = buffer;
				}
				delete[]buffer;
			}
		}
	}
	va_end(args);
	return str;
}


//////////////////////     public functions    //////////////////////

// encode any amd64 shellcode into alphanumeric shellcode
/*
	shellcode：   需要编码的机器码
	length：      机器码长度
	addrRegister: 指向shellcode附近的寄存器名称，默认rax（因为需要smc）
	offset：      这个字段的意思为 addrRegister + offset == encoder的起始地址，默认0

	地址构成：
	reg --> xxxxx  \
			xxxxx  | pre_len (adjust addr to rax)
			xxxxx  /
	reg+off yyyyy  \
			yyyyy  | decoder
			yyyyy  /
			zzzzz  \
			zzzzz  | encoded shellcode
			zzzzz  |
			zzzzz  /
*/
const char* AE64::Encode(const unsigned char* shellcode, size_t length, x64Register addrRegister, size_t offset) {
	clock_t oldClock;
	clock_t newClock;

	oldClock = clock();

	// 1. get prologue
	bytes prologue = GenPrologue(addrRegister);
	size_t prologueLength = prologue.length();
	cerr << "[+] prologue generated" << endl;

	// 2. get encoded shellcode
	bytes rawShellcode = bytes(shellcode, length);
	vector<EncodeInfoStruc> encodeInfo;
	bytes encodedShellcode = GenEncodedShellcode(rawShellcode, encodeInfo);
	cerr << "[+] encoded shellcode generated" << endl;

	// 3. build decoder
	size_t totalSpace = prologueLength;
	size_t nopLength = 0;
	bytes decoder;
	while (true) {
		cerr << "[*] build decoder, try free space: " << totalSpace << " ..." << endl;
		decoder = GenDecoder(encodeInfo, (unsigned short)(offset + totalSpace));
		size_t decoderLength = decoder.length();
		size_t trueLength = prologueLength + decoderLength;
		if (totalSpace >= trueLength && totalSpace - trueLength <= 100) {
			// suitable length, not too long and not too short
			nopLength = totalSpace - trueLength;
			break;
		}
		totalSpace = trueLength;
	}
	bytes res;
	size_t size;

	res = prologue + decoder;
	for (size_t i = 0; i < nopLength / 2; ++i) {
		res += nop2;
	}
	if (nopLength % 2) {
		res += nop;
	}
	res += encodedShellcode;
	size = res.length();
	for (size_t i = 0; i < size; i++) {
		if (!isalnum(res[i])) {
			cerr << "[-] find non-alphanumeric code < 0x";
			cerr << hex << (int)res[i] << dec;
			cerr << " > in final shellcode, this should not happen" << endl;
			cerr << res << endl;
			return "";
		}
	}

	newClock = clock();

	cerr << "[+] Alphanumeric shellcode generate successfully!" << endl;
	cerr << endl;
	cerr << "============  Summary  ============" << endl;
	cerr << left << setw(22) << "Regsiter: " << x64RegisterStr[addrRegister] << endl;
	cerr << left << setw(22) << "Offset: " << offset << endl;
	cerr << left << setw(22) << "Total length: " << res.length() << endl;
	cerr << left << setw(22) << "Original length: " << length << endl;
	cerr << left << setw(22) << "Encode efficiency: " << 100 * (double)res.length() / length << "%" << endl;
	cerr << left << setw(22) << "Time cost:" << (double)(newClock - oldClock) / (CLOCKS_PER_SEC / 1000) << "ms" << endl;
	cerr << "===================================\n" << endl;

	size_t tmpsize;
	return (char*)res.GetCopy(tmpsize);
}
