#include "bytes.h"

#include <stdexcept>
#include <cstring>

using namespace openssl_tools;

bytes::bytes(const std::string& _str):
	data(_str.size(), '\0') {

	byte * b=reinterpret_cast<byte *>(const_cast<char *>(_str.c_str()));
	std::memcpy(&data[0], b, _str.size());		
}

bytes::bytes(size_t _size):
	data(_size, '\0') {

}

bytes::bytes(const char * _data, size_t _size):
	data(_size, '\0') {

	//Fuck the world.
	byte * b=reinterpret_cast<byte *>(const_cast<char *>(_data));

	//TODO: Check me, where am I being called that changing _size for 
	//strlen(_data) makes me go boom??
	//std::memcpy(&data[0], b, _size);
	std::memcpy(&data[0], b, strlen(_data));
}

bytes::bytes(const bytes& _other):
	data(_other.size(), '\0') {

	std::memcpy(&data[0], &_other.data[0], _other.size());
}

bytes::bytes(const bytes& _other, size_t _size):
	data(_size, '\0') {

	size_t copysize=_size > _other.size()
		? _other.size()
		: _size;

	std::memcpy(&data[0], &_other.data[0], copysize);
}

bytes::~bytes() {

	std::memset(&data[0], '\0', size());		
}


bytes bytes::operator+(const bytes& _other) {

	bytes result{*this, size()+_other.size()};
	std::memcpy(&result.data[0]+size(), &_other.data[0], _other.size());

	return result;
}

bytes& bytes::operator+=(const bytes& _other) {

	data.resize(size()+_other.size(), '\0');
	std::memcpy(&data[0]+size(), &_other.data[0], _other.size());
	return *this;
}	

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
	//TODO: Are there not vector implementations for this????
	std::memcpy(&result[0], &data[0]+_begin, _len);	
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