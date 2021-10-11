cmake_minimum_required(VERSION 3.16)
project(bitmessage C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(src)

add_compile_options(-g -Wall)

target_link_libraries(bitmessage crypto pthread)