cmake_minimum_required(VERSION 4.0)
project(pylibbpf)

add_subdirectory(pybind11)
pybind11_add_module(pylibbpf src/main.cpp)

include(ExternalProject)
ExternalProject_Add(
  libbpf_build
  PREFIX libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND
    make BUILD_STATIC_ONLY=1 OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf INCLUDEDIR= LIBDIR= UAPIDIR=
    install install_uapi_headers
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build)

# Define a static library target pointing to the built libbpf.a
add_library(libbpf_static STATIC IMPORTED GLOBAL)

set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include)

set_target_properties(
  libbpf_static
  PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a"
             INTERFACE_INCLUDE_DIRECTORIES "${LIBBPF_INCLUDE_DIRS}")
# Ensure build order: external project builds before linking
add_dependencies(libbpf_static libbpf_build)
add_dependencies(pylibbpf libbpf_static)

# Version info
target_compile_definitions(pylibbpf
                           PRIVATE VERSION_INFO=${PYLIBBPF_VERSION_INFO})

# Link the actual library target
target_link_libraries(pylibbpf PRIVATE libbpf_static)
