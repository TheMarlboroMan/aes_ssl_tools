#ifndef PACKS_H
#define PACKS_H

#include <vector>
#include <string>
#include <mutex>

#include <openssl_tools/bytes.h>

struct crypt_pack {

	openssl_tools::bytes		key, iv, message;
};

struct full_pack {

	openssl_tools::bytes		key, iv, message;
	std::string					payload;
};

struct results_base_pack {

	std::mutex					mt;
	bool						fail=false;
	bool						is_fail() const {return fail;}
	void						set_fail() {fail=true;}
};

struct crypt_results_pack:
	public results_base_pack {

	std::vector<crypt_pack>			data;

									crypt_results_pack(size_t _size) {data.reserve(_size);}
	void							add(const crypt_pack& _data) {

		std::lock_guard<std::mutex> lock{mt};
		data.push_back(_data);
	}
};

struct full_results_pack:
	public results_base_pack {

	std::vector<full_pack>			data;
									full_results_pack(size_t _size) {data.reserve(_size);}
	void							add(const full_pack& _data) {

		std::lock_guard<std::mutex> lock{mt};
		data.push_back(_data);
	}
};

struct plain_results_pack:
	public results_base_pack {

	std::vector<std::string>		data;
									plain_results_pack(size_t _size) {data.reserve(_size);}
	void							add(const std::string& _data) {

		std::lock_guard<std::mutex> lock{mt};
		data.push_back(_data);
	}
};

#endif