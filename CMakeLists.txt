cmake_minimum_required(VERSION 3.5.1)
project(openssl_tools)
set(CMAKE_BUILD_TYPE release)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -Wundef -Wcast-align -Wwrite-strings -Wlogical-op -Wmissing-declarations -Wredundant-decls -Wshadow -Woverloaded-virtual -Wno-deprecated -ansi -pedantic -fno-rtti -std=c++14)

set(SOURCE "")
add_subdirectory("${PROJECT_SOURCE_DIR}/src")

add_library(openssl_tools SHARED ${SOURCE})
install(TARGETS openssl_tools DESTINATION /usr/local/lib)
install(DIRECTORY src/class/ DESTINATION /usr/local/include/openssl_tools FILES_MATCHING PATTERN "*.h")

add_executable(main src/main.cpp)
target_link_libraries(main openssl_tools ssl crypto)

add_executable(threads src/threading.cpp)
target_link_libraries(threads pthread openssl_tools ssl crypto)

add_executable(drill src/drill.cpp)
target_link_libraries(drill pthread openssl_tools ssl crypto)

add_executable(encrypt src/encrypt.cpp)
target_link_libraries(encrypt ssl crypto openssl_tools)

add_executable(decrypt src/decrypt.cpp)
target_link_libraries(decrypt ssl crypto openssl_tools)

add_executable(concat src/concat.cpp)
target_link_libraries(concat openssl_tools ssl crypto pthread)
