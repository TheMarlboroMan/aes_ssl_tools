cmake_minimum_required(VERSION 3.5.1)
project(openssl_thread_manager)
set(CMAKE_BUILD_TYPE release)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -Wundef -Wcast-align -Wwrite-strings -Wlogical-op -Wmissing-declarations -Wredundant-decls -Wshadow -Woverloaded-virtual -Wno-deprecated -ansi -pedantic -fno-rtti -std=c++14)

set(SOURCE "")
add_subdirectory("${PROJECT_SOURCE_DIR}/src")

add_library(openssl_thread_manager STATIC ${SOURCE})
install(TARGETS openssl_thread_manager DESTINATION /usr/lib)
install(DIRECTORY src/class/ DESTINATION include/openssl_thread_manager FILES_MATCHING PATTERN "*.h")