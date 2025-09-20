cmake_minimum_required(VERSION 4.0)
project(pylibbpf)

add_subdirectory(pybind11)
pybind11_add_module(pylibbpf src/main.cpp)

# EXAMPLE_VERSION_INFO is defined by setup.py and passed into the C++ code as a
# define (VERSION_INFO) here.
target_compile_definitions(pylibbpf
                           PRIVATE VERSION_INFO=${EXAMPLE_VERSION_INFO})
