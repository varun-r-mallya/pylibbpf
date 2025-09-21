#include <pybind11/pybind11.h>
#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)

extern "C" {
#include "libbpf.h"
}
#include "core/bpf_program.h"
#include "core/bpf_exception.h"

namespace py = pybind11;

PYBIND11_MODULE(pylibbpf, m) {
    m.doc() = R"pbdoc(
        Pylibbpf - libbpf bindings for Python
        -----------------------

        .. currentmodule:: pylibbpf

        .. autosummary::
           :toctree: _generate

           BpfProgram
           BpfException
    )pbdoc";

    // Register the custom exception
    py::register_exception<BpfException>(m, "BpfException");

    py::class_<BpfProgram>(m, "BpfProgram")
     .def(py::init<const std::string&>())
     .def(py::init<const std::string&, const std::string&>())
     .def("load", &BpfProgram::load)
     .def("attach", &BpfProgram::attach)
     // .def("detach", &BpfProgram::detach)
     .def("is_loaded", &BpfProgram::is_loaded)
     .def("is_attached", &BpfProgram::is_attached);

#ifdef VERSION_INFO
    m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
    m.attr("__version__") = "dev";
#endif
}
