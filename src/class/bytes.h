#ifndef OPENSSL_TOOLS_BYTES_H
#define OPENSSL_TOOLS_BYTES_H

#include <iostream>
#include <vector>

namespace openssl_tools {

//TODO: Add ranged for iterators.

struct bytes {

	using byte=unsigned char;

	//!Create a sequence of bytes from a std::string.
								bytes(const std::string& _str);		

	//!Creates a sequence of bytes with _size length, initialized to \0.								
								bytes(size_t _size);

	//Creates a sequece of bytes up to _size bytes from data. If _data is 
	//shorter than _size, prepare for an afternoon of debugging.
								bytes(const byte * _data, size_t _size);

	//Creates a sequence of data of _size length, and fills it with _copy bytes
	//from _data. _data should have at least _size bytes...
								bytes(const byte * _data, size_t _copy, size_t _size);

	//!Copy constructor.
								bytes(const bytes&);

	//!Partial copy constructor. Will attempt to copy _size items from _other,
	//!unless _other.size() is smaller than _size, in which case it will copy
	//!_other.size().
								bytes(const bytes& _other, size_t _size);

	//!Class destructor, wipes the memory, just in case someone is 
	//!eavesdropping. Not secure enough, but hey...
								~bytes();

	//!Creates a new instance from the addition of two.
	bytes 						operator+(const bytes& _other);
	
	//!Concatenates bytes.
	bytes&						operator+=(const bytes& _other);
	//!Concatenates a single byte. If you want to do more than this, perhaps
	//!you should consider creating a new bytes instance from that data.
	//bytes&						operator+=(const byte);
	//bytes&					operator+=(const byte *)
	//bytes&					operator+=(const std::string&)

	//!Gets a new chunk of bytes from "begin" until _len bytes. If _len is 
	//!zero it just gets the data to the end.
	bytes 						range(size_t _begin, size_t _len=0);

	//!Low level access to individual items.
	byte * 						offset(size_t _offset);

	//!Low level access to individual items.
	const byte * 				offset(size_t _offset) const;

	byte&						at(size_t);
	const byte&					at(size_t) const;
	byte&						operator[](size_t);

	//!Low level implicit casts for OpenSSL functions.
	operator const byte * 		() const;

	//!Low level implicit casts for OpenSSL functions. Please, look away.
	operator byte * 			();

	//!Low level implicit casts for std::string building 0_o. Removes padding
	//!so unless this is exactly what you want do do...
	std::string 				to_string() const;

	size_t						size() const {return data.size();}

	std::vector<byte>&			get() {return data;}
	const std::vector<byte>&	get() const {return data;}

	private:

	std::vector<byte> 			data;
};

std::ostream& operator<<(std::ostream& os, const bytes& _bytes);

}

#endif