#include "openssl_thread_manager.h"

#include <stdexcept>

size_t openssl_thread_manager::instances=0;
std::vector<std::mutex> openssl_thread_manager::mutex_buf(CRYPTO_num_locks());

openssl_thread_manager::openssl_thread_manager() {

	if(!instances) {
		++instances;
		CRYPTO_set_id_callback(id_function);
		CRYPTO_set_locking_callback(locking_function);
	}
}

openssl_thread_manager::~openssl_thread_manager() {

	--instances;

	if(!instances) 	{
		CRYPTO_set_id_callback(nullptr);
		CRYPTO_set_locking_callback(nullptr);
	}
}

void locking_function(int mode, int n, const char * /*file*/ , int /*line*/) {

	try {
		if(mode & CRYPTO_LOCK) {
			openssl_thread_manager::mutex_buf[n].lock();
		}
		else {
			openssl_thread_manager::mutex_buf[n].unlock();
		}
	}
	catch(std::exception& e) {
		//This would clearly spell doom.
		throw std::runtime_error(std::string("error locking thread ")+e.what());
	}
}
 
unsigned long id_function(void) {
	return ((unsigned long)pthread_self);
}

void openssl_thread_manager::check_max_threads(size_t th) {

	if(th > (size_t)CRYPTO_num_locks()) {
		
		throw std::runtime_error("Up to "+std::to_string(CRYPTO_num_locks())+" threads are supported for SSL compatibility. "+std::to_string(th)+" specified. Lower the thread count.");
	}
}
