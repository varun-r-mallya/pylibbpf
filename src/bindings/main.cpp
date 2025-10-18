#include <pybind11/pybind11.h>
#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)

extern "C" {
#include <libbpf.h>
}

#include "core/bpf_object.h"
#include "core/bpf_program.h"
#include "core/bpf_exception.h"
#include "core/bpf_map.h"
#include "core/bpf_perf_buffer.h"

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

    // BpfObject
    py::class_<BpfObject, std::shared_ptr<BpfObject>>(m, "BpfObject")
        .def(py::init<std::string>(), py::arg("object_path"))
        .def("load", &BpfObject::load)
        .def("is_loaded", &BpfObject::is_loaded)
        .def("get_program_names", &BpfObject::get_program_names)
        .def("get_program", &BpfObject::get_program, py::arg("name"))
        .def("attach_all", &BpfObject::attach_all)
        .def("get_map_names", &BpfObject::get_map_names)
        .def("get_map", &BpfObject::get_map, py::arg("name"));

    // BpfProgram
    py::class_<BpfProgram, std::shared_ptr<BpfProgram>>(m, "BpfProgram")
        .def("attach", &BpfProgram::attach)
        .def("detach", &BpfProgram::detach)
        .def("is_attached", &BpfProgram::is_attached)
        .def("get_name", &BpfProgram::get_name);

    // BpfMap
    py::class_<BpfMap, std::shared_ptr<BpfMap>>(m, "BpfMap")
        .def("lookup", &BpfMap::lookup, py::arg("key"))
        .def("update", &BpfMap::update, py::arg("key"), py::arg("value"))
        .def("delete_elem", &BpfMap::delete_elem, py::arg("key"))
        .def("get_next_key", &BpfMap::get_next_key, py::arg("key") = py::none())
        .def("items", &BpfMap::items)
        .def("keys", &BpfMap::keys)
        .def("values", &BpfMap::values)
        .def("get_name", &BpfMap::get_name)
        .def("get_fd", &BpfMap::get_fd)
        .def("get_type", &BpfMap::get_type)
        .def("get_key_size", &BpfMap::get_key_size)
        .def("get_value_size", &BpfMap::get_value_size)
        .def("get_max_entries", &BpfMap::get_max_entries);

    py::class_<BpfPerfBuffer>(m, "BpfPerfBuffer")
            .def(py::init<int, int, py::function, py::object>(),
                 py::arg("map_fd"),
                 py::arg("page_cnt") = 8,
                 py::arg("callback"),
                 py::arg("lost_callback") = py::none())
            .def("poll", &BpfPerfBuffer::poll, py::arg("timeout_ms") = -1)
            .def("consume", &BpfPerfBuffer::consume);


#ifdef VERSION_INFO
    m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
    m.attr("__version__") = "dev";
#endif
}
