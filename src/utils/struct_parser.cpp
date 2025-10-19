#include "struct_parser.h"
#include "core/bpf_exception.h"

StructParser::StructParser(py::dict structs) {
  for (auto item : structs) {
    std::string name = py::str(item.first);
    struct_types_[name] = py::reinterpret_borrow<py::object>(item.second);
  }
}

py::object StructParser::parse(const std::string &struct_name, py::bytes data) {
  auto it = struct_types_.find(struct_name);
  if (it == struct_types_.end()) {
    throw BpfException("Unknown struct: " + struct_name);
  }

  py::object struct_type = it->second;

  // Use ctypes.from_buffer_copy() to create struct from bytes
  return struct_type.attr("from_buffer_copy")(data);
}

bool StructParser::has_struct(const std::string &struct_name) const {
  return struct_types_.find(struct_name) != struct_types_.end();
}
