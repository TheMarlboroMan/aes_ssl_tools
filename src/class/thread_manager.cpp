#include "thread_manager.h"

#include <stdexcept>

using namespace openssl_tools;

size_t openssl_tools::thread_manager::instances=0;
std::vector<std::mutex> openssl_tools::thread_manager::mutex_buf(CRYPTO_num_locks());

thread_manager::thread_manager() {

	if(!instances) {
		++instances;
		CRYPTO_set_id_callback(id_function);
		CRYPTO_set_locking_callback(locking_function);
	}
}

thread_manager::~thread_manager() {

	--instances;

	if(!instances) 	{
		CRYPTO_set_id_callback(nullptr);
		CRYPTO_set_locking_callback(nullptr);
	}
}

void thread_manager::check_max_threads(size_t th) {

	if(th > (size_t)CRYPTO_num_locks()) {
		
		throw std::runtime_error("Up to "+std::to_string(CRYPTO_num_locks())+" threads are supported for SSL compatibility. "+std::to_string(th)+" specified. Lower the thread count.");
	}
}

void openssl_tools::locking_function(int mode, int n, const char * /*file*/ , int /*line*/) {

	try {
		if(mode & CRYPTO_LOCK) {
			openssl_tools::thread_manager::mutex_buf[n].lock();
		}
		else {
			openssl_tools::thread_manager::mutex_buf[n].unlock();
		}
	}
	catch(std::exception& e) {
		//This would clearly spell doom.
		throw std::runtime_error(std::string("error locking thread ")+e.what());
	}
}
 
unsigned long openssl_tools::id_function(void) {
	return ((unsigned long)pthread_self);
}