#include <iostream>
#include <fstream>
#include <cmdline.h>
#include "ae64.h"
#include "bytes.h"

using namespace std;

int main(int argc, char** argv) {
	cmdline::parser parser;
	parser.add<string>("reg", '\0', "Register who contain the address that related to where shellcode execute.", true);
	parser.add<int>("off", '\0', "The offset between register's value and the address that our shellcode execute.", false, 0, cmdline::range(0, 0xffff));
	parser.add<string>("input", 'i', "Input filename", false, "stdin");
	parser.add<string>("format", 'f', "Input format, can be either asm code or bytes. (asm/bytes)", false, "asm", cmdline::oneof<string>("asm", "bytes"));
	parser.add<string>("output", 'o', "Output filename", false, "stdout");

	parser.parse_check(argc, argv);

	// do some check
	string regName = parser.get<string>("reg");
	int offset = parser.get<int>("off");
	x64Register reg = UNK_REG;
	transform(regName.begin(), regName.end(), regName.begin(), [](unsigned char c) { return tolower(c); });
	auto iter = x64RegisterStr.begin();
	while (iter != x64RegisterStr.end()) {
		if (iter->second == regName) {
			reg = iter->first;
			break;
		}
		iter++;
	}
	if (reg == UNK_REG) {
		cerr << "[-] Register name " << parser.get<string>("reg") << " is invaild" << endl;
		return 1;
	}

	// init class object 
	ks_err err;
	AE64 ae64 = AE64(err);
	if (err != KS_ERR_OK) {
		cerr << "[-] Init keystone fail" << endl;
		return 1;
	}

	// parsing input 
	string inputFormat = parser.get<string>("format");
	string inputFileName = parser.get<string>("input");
	bytes shellcode;
	FILE* fp = stdin;
	vector<char> inputVector;
	char buffer[0x1000];
	int len = 0;
	memset(buffer, 0, 0x1000);
	if (inputFileName != "stdin") {
		fp = fopen(inputFileName.c_str(), "rb");
		if (!fp) {
			cerr << "[-] open file " << inputFileName << " fail" << endl;
			return 1;
		}
	}
	while ((len = fread(buffer, 1, 0xfff, fp)) > 0) {
		inputVector.insert(inputVector.end(), buffer, buffer + len);
		memset(buffer, 0, 0x1000);
	}
	string input(inputVector.begin(), inputVector.end());
	if (inputFormat == "asm") {
		shellcode = ae64.GenMachineCode(input);
		if (shellcode.length() == 0) {
			cerr << "[-] Compile asm code fail" << endl;
			return 1;
		}
	}
	else {
		shellcode = input;
		if (shellcode.length() == 0) {
			cerr << "[-] Can't get machine code" << endl;
			return 1;
		}
	}
	if (inputFileName != "stdin") {
		fclose(fp);
	}

	// encode shellcode
	size_t length = 0;
	unsigned char* sc = shellcode.GetCopy(length);
	const char* res = ae64.Encode(sc, length, reg, offset);

	// output
	string outputFileName = parser.get<string>("output");
	if (outputFileName == "stdout") {
		cout << res << endl;
	}
	else {
		FILE* fp = fopen(outputFileName.c_str(), "w");
		if (!fp) {
			cerr << "[-] Open output file " << outputFileName << " fail" << endl;
			return 1;
		}
		fwrite(res, 1, strlen(res), fp);
		fclose(fp);
	}
	return 0;
}
