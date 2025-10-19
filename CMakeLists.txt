cmake_minimum_required(VERSION 4.0)
project(pylibbpf)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# pybind11
include_directories(${CMAKE_SOURCE_DIR}/src)
add_subdirectory(pybind11)
pybind11_add_module(
  pylibbpf
  # Core
  src/core/bpf_program.h
  src/core/bpf_exception.h
  src/core/bpf_map.h
  src/core/bpf_object.h
  src/core/bpf_program.cpp
  src/core/bpf_map.cpp
  src/core/bpf_object.cpp
  # Maps
  src/maps/perf_event_array.h
  src/maps/perf_event_array.cpp
  # Utils
  src/utils/struct_parser.h
  src/utils/struct_parser.cpp
  # Bindings
  src/bindings/main.cpp)

# --- libbpf build rules ---
set(LIBBPF_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src)
set(LIBBPF_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_A ${LIBBPF_BUILD_DIR}/libbpf.a)

add_custom_command(
  OUTPUT ${LIBBPF_A}
  COMMAND make BUILD_STATIC_ONLY=1 OBJDIR=${LIBBPF_BUILD_DIR} CFLAGS="-fPIC"
          LDFLAGS="-fPIC" -C ${LIBBPF_SRC_DIR}
  WORKING_DIRECTORY ${LIBBPF_SRC_DIR}
  COMMENT "Building libbpf.a"
  VERBATIM)

add_custom_target(libbpf_build ALL DEPENDS ${LIBBPF_A})

# Define static lib as imported
add_library(libbpf_static STATIC IMPORTED GLOBAL)
set_target_properties(
  libbpf_static
  PROPERTIES
    IMPORTED_LOCATION ${LIBBPF_A}
    INTERFACE_INCLUDE_DIRECTORIES
    "${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include;${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src"
)

add_dependencies(libbpf_static libbpf_build)

# Link pybind11 module against libbpf
target_link_libraries(pylibbpf PRIVATE libbpf_static elf)

# Version info for Python extension
target_compile_definitions(pylibbpf
                           PRIVATE VERSION_INFO=${PYLIBBPF_VERSION_INFO})
