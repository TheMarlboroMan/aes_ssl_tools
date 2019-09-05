#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <mutex>

#include "class/bytes.h"
#include "class/random.h"
#include "class/exception.h"

void do_something();

std::mutex mtx;

int main(int argc, char ** argv) {

	if(1==argc) {
		std::cerr<<"use "<<argv[0]<<" numthreads"<<std::endl;
		return 1;
	}

	try {

		size_t total=std::atoi(argv[1]);
		std::vector<std::thread> tasks;
		tasks.reserve(total);
		for(size_t i=0; i<total; i++) {

			tasks.push_back(
				std::thread(do_something)
			);
		}

		for(auto& t : tasks) {
			t.join();
		}

		return 0;
	}
	catch(std::exception& e) {
		std::cerr<<"error: "<<e.what()<<std::endl;
		return 1;
	}
}

void do_something() {

	try {
		std::lock_guard<std::mutex> lock{mtx};
		auto bt=openssl_tools::random_bytes(16);
	}
	catch(std::exception& e) {
		std::cerr<<"fuck "<<e.what()<<std::endl;
	}
}
