# Py-libbpf
<p align="center">
<a href="https://www.python.org/downloads/release/python-3080/"><img src="https://img.shields.io/badge/python-3.8-blue.svg"></a>
<a href="https://pypi.org/project/pylibbpf"><img src="https://badge.fury.io/py/pylibbpf.svg"></a>
</p>
This library provides Python bindings for libbpf on Linux to make loading of eBPF object files easier. This is meant to
be used along with `pythonbpf`, the eBPF Python DSL compiler. This library makes it possible to attach these programs to
events in the kernel right from inside Python.

# IN DEVELOPMENT. DO NOT USE.

## Prerequisites

* A compiler with C++11 support
* Pip 10+ or CMake >= 4.1
* Ninja or Pip 10+


## Installation

Just clone this repository and pip install. Note the `--recursive` option which is
needed for the pybind11 submodule:

```bash
sudo apt install libelf-dev
git clone --recursive https://github.com/varun-r-mallya/pylibbpf.git
pip install .
```

With the `setup.py` file included in this example, the `pip install` command will
invoke CMake and build the pybind11 module as specified in `CMakeLists.txt`.

## Development
Do this before running to make sure Python can manipulate bpf programs without sudo
```bash
sudo setcap cap_bpf,cap_sys_admin+ep /usr/bin/python3.12
```

## Building the documentation
The documentation here is still boilerplate.
