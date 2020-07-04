#pragma once
#include <iostream>
#include <string>
#include <ostream>

using namespace std;

class bytes {
private:
	unsigned char* data = nullptr;
	unsigned char dummy = 0;
	size_t size = 0;

	unsigned char* MemoryCopy(const unsigned char* src, size_t size);
public:
	bytes();
	bytes(const unsigned char* s);
	bytes(const char* s);
	bytes(string s);
	bytes(const unsigned char* s, size_t len);
	bytes(const bytes& b);
	~bytes();

	void operator=(const unsigned char* s);
	void operator=(const bytes& b);
	bytes operator+(const unsigned char* s);
	bytes operator+(const bytes& b);
	void operator+=(const bytes& b);
	friend ostream& operator<<(ostream& os, const bytes& _bytes);
	unsigned char& operator[](size_t idx);
	size_t length();
	unsigned char* GetCopy(size_t& len);

};

bytes operator+(const unsigned char* s, const bytes& b);