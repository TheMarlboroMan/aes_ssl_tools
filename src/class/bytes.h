#ifndef OPENSSL_TOOLS_BYTES_H
#define OPENSSL_TOOLS_BYTES_H

#include <iostream>
#include <vector>

namespace openssl_tools {

//TODO: Add ranged for iterators.

struct bytes {

	using byte=unsigned char;

								bytes(const std::string& _str);		
								bytes(size_t _size);

	//This is absolutely intentional: size must be given for padding purposes,
	//as the string will be padded along. This is needed for the crypt 
	//part, in which we create instances of this from other data!!!!.	
								bytes(const char * _data, size_t _size);
								bytes(const bytes&);
								bytes(const bytes& _other, size_t _size);

	//!Class destructor, wipes the memory, just in case someone is 
	//!eavesdropping. Not secure enough, but hey...
								~bytes();

	bytes 						operator+(const bytes& _other);
	bytes&						operator+=(const bytes& _other);

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