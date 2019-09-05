#include "bytes.h"

#include <stdexcept>
#include <algorithm>
#include <cstring>

using namespace openssl_tools;

bytes::bytes(const std::string& _str):
	data(_str.size(), '\0') {
	
	byte * b=reinterpret_cast<byte *>(const_cast<char *>(_str.c_str()));
	std::memcpy(&data[0], b, _str.size());		

//	byte src[_str.size()]={reinterpret_cast<byte *>(const_cast<char *>(_str.c_str()))};
//	std::copy(std::begin(src), std::end(src), std::begin(data));

}

bytes::bytes(size_t _size):
	data(_size, '\0') {

}

bytes::bytes(const byte * _bytes, size_t _size):
	data(_size, '\0') {

	std::memcpy(&data[0], _bytes, _size);
}

bytes::bytes(const byte * _bytes, size_t _copy, size_t _size):
	data(_size, '\0') {

	std::memcpy(&data[0], _bytes, _copy);
}

bytes::bytes(const bytes& _other):
	data(_other.size(), '\0') {

	std::copy(std::begin(_other.data), std::end(_other.data), std::begin(data));
}

bytes::bytes(const bytes& _other, size_t _size):
	data(_size, '\0') {

	size_t copysize=_size > _other.size()
		? _other.size()
		: _size;

	std::copy(std::begin(_other.data), std::begin(_other.data)+copysize, std::begin(data));
}

bytes::~bytes() {

	std::fill(std::begin(data), std::end(data), '\0');
}


bytes bytes::operator+(const bytes& _other) {

	bytes result{*this, size()+_other.size()};
	std::copy(std::begin(_other.data), std::end(_other.data), std::begin(result.data)+size());

	return result;
}

bytes& bytes::operator+=(const bytes& _other) {

	size_t prevsize=size();
	data.resize(size()+_other.size(), '\0');
	std::copy(std::begin(_other.data), std::end(_other.data), std::begin(data)+prevsize);
	return *this;
}

/*
bytes& bytes::operator+=(bytes::byte _byte) {

	data.resize(size()+1, '\0');
	std::memcpy(std::end(data), &_byte, 1);
	return *this;
}
*/

//!Gets a new chunk of bytes from "begin" until _len bytes. If _len is 
//!zero it just gets the data to the end.
bytes bytes::range(size_t _begin, size_t _len) {

	if(0==_len) {
		_len=size()-_begin;
	}

	if(_begin >= size() || _begin+_len > size()) {
		throw std::runtime_error("invalid values to bytes::range");
	}

	bytes result{_len};
	std::copy(std::begin(data)+_begin, std::begin(data)+_begin+_len, std::begin(result.data));
	return result;
}

//!Low level access to individual items.
bytes::byte * bytes::offset(size_t _offset) {

	if(_offset >= size()) {
		throw std::runtime_error("invalid offset to bytes::offset");
	}

	return reinterpret_cast<byte *>(&data[0]+_offset);
}

//!Low level access to individual items.
const bytes::byte * bytes::offset(size_t _offset) const {

	//TODO: Implement one in terms of the other.
	if(_offset >= size()) {
		throw std::runtime_error("invalid offset to bytes::offset");
	}

	return reinterpret_cast<const byte *>(&data[0]+_offset);
}

//!Low level implicit casts for OpenSSL functions.

bytes::operator const bytes::byte *() const {

	return reinterpret_cast<const bytes::byte *>(&data[0]);
}

//!Low level implicit casts for OpenSSL functions. Please, look away.
bytes::operator bytes::byte * () {

	return reinterpret_cast<bytes::byte *>(&data[0]);
}

//!Low level implicit casts for std::string building 0_o. Removes padding
//!so unless this is exactly what you want do do...
std::string bytes::to_string() const {

	//Calculate padding....
	size_t padding=0;
	for(int i=size()-1; i>=0 ; --i) {
		if('\0'!=data[i]) {
			break;
		}
		++padding;
	}

	return std::string{reinterpret_cast<const char *>(&data[0]), size()-padding};
} 

bytes::byte& bytes::at(size_t _index) {

	//TODO: Avoid duplication...
	
	if(_index >= size()) {
		throw std::out_of_range("bytes::at out of range");
	}

	return data[_index];
}

const bytes::byte&	bytes::at(size_t _index) const {

	if(_index >= size()) {
		//TODO: Should be other exception?
		throw std::out_of_range("bytes::at out of range");
	}

	return data[_index];
}

bytes::byte& bytes::operator[](size_t _index) {

	return data[_index];
}

std::ostream& openssl_tools::operator<<(std::ostream& os, const bytes& _bytes) {

	os<<_bytes.to_string();
	return os;
}