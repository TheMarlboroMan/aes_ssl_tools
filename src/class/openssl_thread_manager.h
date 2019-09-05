#ifndef OPENSSL_THREAD_MANAGER_H
#define OPENSSL_THREAD_MANAGER_H

#include <vector>
#include <mutex>

#include <openssl/err.h>

namespace openssl_tools {

//These are required by openssl in multithreading mode.
void locking_function(int mode, int n, const char * file, int line);
unsigned long id_function(void);

class openssl_thread_manager {
	public:

						openssl_thread_manager();
						~openssl_thread_manager();
	void				check_max_threads(size_t);

	private:

						openssl_thread_manager(const openssl_thread_manager&)=delete;
						openssl_thread_manager& operator=(const openssl_thread_manager&)=delete;

	static size_t					instances;
	static std::vector<std::mutex>			mutex_buf;

	friend void locking_function(int mode, int n, const char * file, int line);
	friend unsigned long id_function(void);
}; 

}

#endif
