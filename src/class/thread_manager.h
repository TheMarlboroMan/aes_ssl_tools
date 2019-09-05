#ifndef OPENSSL_TOOLS_THREAD_MANAGER_H
#define OPENSSL_TOOLS_THREAD_MANAGER_H

#include <vector>
#include <mutex>

#include <openssl/err.h>

namespace openssl_tools {

//These are required by openssl in multithreading mode.
void locking_function(int mode, int n, const char * file, int line);
unsigned long id_function(void);

class thread_manager {
	public:

						thread_manager();
						~thread_manager();
	void				check_max_threads(size_t);

	private:

						thread_manager(const thread_manager&)=delete;
						thread_manager& operator=(const thread_manager&)=delete;

	static size_t					instances;
	static std::vector<std::mutex>			mutex_buf;

	friend void locking_function(int mode, int n, const char * file, int line);
	friend unsigned long id_function(void);
}; 

}

#endif
