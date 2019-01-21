# cmake_minimum_required(VERSION <specify CMake version here>)
project(dark-souls-remastered-sl2-unpacker)

set(CMAKE_CXX_STANDARD 11)

add_executable(dark-souls-remastered-sl2-unpacker main.cpp aes.c aes.hpp aes.h)