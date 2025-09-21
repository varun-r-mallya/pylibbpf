#include <pybind11/pybind11.h>
#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)

extern "C" {
#include <libbpf.h>
}

#include "core/bpf_program.h"
#include "core/bpf_exception.h"
#include "core/bpf_map.h"

namespace py = pybind11;

PYBIND11_MODULE(pylibbpf, m) {
    m.doc() = R"pbdoc(
        Pylibbpf - libbpf bindings for Python
        -----------------------

        .. currentmodule:: pylibbpf

        .. autosummary::
           :toctree: _generate

           BpfProgram
           BpfMap
           BpfException
    )pbdoc";

    // Register the custom exception
    py::register_exception<BpfException>(m, "BpfException");

    py::class_<BpfProgram>(m, "BpfProgram")
            .def(py::init<const std::string &>())
            .def(py::init<const std::string &, const std::string &>())
            .def("load", &BpfProgram::load)
            .def("attach", &BpfProgram::attach)
            .def("destroy", &BpfProgram::destroy)
            .def("load_and_attach", &BpfProgram::load_and_attach)
            .def("is_loaded", &BpfProgram::is_loaded)
            .def("is_attached", &BpfProgram::is_attached);

    py::class_<BpfMap>(m, "BpfMap")
            .def(py::init<BpfProgram *, py::object &>())
            .def("lookup", &BpfMap::lookup)
            .def("update", &BpfMap::update)
            .def("delete", &BpfMap::delete_elem)
            .def("get_next_key", &BpfMap::get_next_key, py::arg("key") = py::none())
            .def("items", &BpfMap::items)
            .def("keys", &BpfMap::keys)
            .def("values", &BpfMap::values)
            .def("get_name", &BpfMap::get_name)
            .def("get_type", &BpfMap::get_type)
            .def("get_key_size", &BpfMap::get_key_size)
            .def("get_value_size", &BpfMap::get_value_size)
            .def("get_max_entries", &BpfMap::get_max_entries)
            .def("__getitem__", &BpfMap::lookup)
            .def("__setitem__", &BpfMap::update)
            .def("__delitem__", &BpfMap::delete_elem);


#ifdef VERSION_INFO
    m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
    m.attr("__version__") = "dev";
#endif
}
