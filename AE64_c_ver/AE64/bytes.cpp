#include <cstring>
#include "bytes.h"

// copy memory to new distance
unsigned char* bytes::MemoryCopy(const unsigned char* src, size_t len) {
	unsigned char* newMem = new unsigned char[len + 1];
	memset(newMem, 0, len + 1);
	memcpy(newMem, src, len);
	return newMem;
}

bytes::bytes() {
	data = nullptr;
	size = 0;
}

bytes::bytes(const unsigned char* s) {
	size_t len = strlen((const char*)s);
	data = MemoryCopy(s, len);
	size = len;
}

bytes::bytes(const char* s) {
	size_t len = strlen(s);
	data = MemoryCopy((unsigned char*)s, len);
	size = len;
}

bytes::bytes(string s) {
	size_t len = s.length();
	data = MemoryCopy((unsigned char*)s.c_str(), len);
	size = len;
}

bytes::bytes(const unsigned char* s, size_t len) {
	data = MemoryCopy(s, len);
	size = len;
}

bytes::bytes(const bytes& b) {
	data = MemoryCopy(b.data, b.size);
	size = b.size;
}

bytes::~bytes() {
	delete[]data;
	size = 0;
}

void bytes::operator=(const unsigned char* s) {
	size_t len = strlen((const char*)s);
	data = MemoryCopy(s, len);
	size = len;
}

void bytes::operator=(const bytes& b) {
	data = MemoryCopy(b.data, b.size);
	size = b.size;
}

bytes bytes::operator+(const unsigned char* s) {
	bytes res = bytes(*this);
	bytes tmp(s);
	res += tmp;
	return res;
}

bytes bytes::operator+(const bytes& b) {
	bytes res = bytes(*this);
	res += b;
	return res;
}

bytes operator+(const unsigned char* s, const bytes& b) {
	bytes res = bytes(s);
	res += b;
	return res;
}

void bytes::operator+=(const bytes& b) {
	size_t oldLen = b.size;
	size_t newLen = oldLen + size;
	unsigned char* newData = new unsigned char[newLen + 1];
	memset(newData, 0, newLen + 1);
	memcpy(newData, data, size);
	memcpy(newData + size, b.data, oldLen);
	delete[]data;
	data = newData;
	size = newLen;
}

ostream& operator<<(ostream& os, const bytes& _bytes) {
	os << "length: " << _bytes.size << ", data: { ";
	os << hex;
	for (size_t i = 0; i < _bytes.size; ++i) {
		os << "0x" << (int)_bytes.data[i] << ", ";
	}
	os << dec;
	os << "}";
	return os;
}

unsigned char& bytes::operator[](size_t idx) {
	// protect overflow
	if (idx >= size || idx < 0) {
		return dummy;
	}
	return data[idx];
}

size_t bytes::length() {
	return size;
}

unsigned char* bytes::GetCopy(size_t& len) {
	unsigned char* res = MemoryCopy(data, size);
	len = size;
	return res;
}
