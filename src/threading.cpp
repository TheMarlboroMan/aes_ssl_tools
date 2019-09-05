#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <mutex>

#include "class/bytes.h"
#include "class/random.h"
#include "class/base_64.h"
#include "class/exception.h"

openssl_tools::bytes generate_random_stuff(size_t);
void base64_drill(size_t);

std::mutex mtx;

int main(int argc, char ** argv) {

	if(3!=argc) {
		std::cerr<<"use "<<argv[0]<<" numthreads bytes"<<std::endl;
		return 1;
	}

	try {

		size_t total=std::atoi(argv[1]);
		std::vector<std::thread> tasks;
		tasks.reserve(total);

		for(size_t i=0; i<total; i++) {
			tasks.push_back(std::thread(generate_random_stuff, std::atoi(argv[2])));
		}
		for(auto& t : tasks) t.join();

		tasks.clear();

		for(size_t i=0; i<total; i++) {
			tasks.push_back(std::thread(base64_drill, std::atoi(argv[2])));
		}
		for(auto& t : tasks) t.join();
		tasks.clear();

		return 0;
	}
	catch(std::exception& e) {
		std::cerr<<"error: "<<e.what()<<std::endl;
		return 1;
	}
}

openssl_tools::bytes generate_random_stuff(size_t _count) {

	try {
		return openssl_tools::random_bytes(_count);		
	}
	catch(std::exception& e) {
		std::lock_guard<std::mutex> lock{mtx};
		std::cerr<<"fuck "<<e.what()<<std::endl;
		return openssl_tools::bytes{0};
	}
}


void base64_drill(size_t _count) {

	try {
		auto bytes=generate_random_stuff(_count);
		auto encoded=openssl_tools::base64_encode(bytes);

		std::lock_guard<std::mutex> lock{mtx};
		std::cout<<encoded<<std::endl;
	}
	catch(std::exception& e) { 
		std::lock_guard<std::mutex> lock{mtx};
		std::cerr<<"fail "<<e.what()<<std::endl;
	}
}