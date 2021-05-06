cmake_minimum_required(VERSION 3.16)
project(SHA_256)

set(CMAKE_CXX_STANDARD 20)

add_executable(SHA_256 main.cpp SHA256.h SHA256.cpp)