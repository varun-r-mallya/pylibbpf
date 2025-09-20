# Py-libbpf
This library provides Python bindings for libbpf on Linux to make loading of eBPF object files easier. This is meant to
be used along with `pythonbpf`, the eBPF Python DSL compiler. This library makes it possible to attach these programs to
events in the kernel right from inside Python.

# Warning
IN DEVELOPMENT. DO NOT USE.

## Prerequisites

* A compiler with C++11 support
* Pip 10+ or CMake >= 4.1
* Ninja or Pip 10+


## Installation

Just clone this repository and pip install. Note the `--recursive` option which is
needed for the pybind11 submodule:

```bash
git clone --recursive https://github.com/varun-r-mallya/pylibbpf.git
pip install .
```

With the `setup.py` file included in this example, the `pip install` command will
invoke CMake and build the pybind11 module as specified in `CMakeLists.txt`.

## Building the documentation
The documentation here is still boilerplate.
