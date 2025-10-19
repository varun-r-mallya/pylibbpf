#ifndef PYLIBBPF_STRUCT_PARSER_H
#define PYLIBBPF_STRUCT_PARSER_H

#include <pybind11/pybind11.h>
#include <string>
#include <unordered_map>

namespace py = pybind11;

class StructParser {
private:
  std::unordered_map<std::string, py::object> struct_types_;

public:
  explicit StructParser(py::dict structs);
  py::object parse(const std::string &struct_name, py::bytes data);
  bool has_struct(const std::string &struct_name) const;
};

#endif
