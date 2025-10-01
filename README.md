<picture>
  <source
    media="(prefers-color-scheme: light)"
    srcset="https://github.com/user-attachments/assets/dbd56f5b-4512-4c82-a404-30bce0ee5207"
    width="450"
    alt="pylibbpf light mode">
  <img
    src="https://github.com/user-attachments/assets/9e873d60-a834-4411-bc0c-361b14502f8b"
    width="450"
    alt="pylibbpf dark mode">
</picture>
<p align="center">
  <!-- PyPI -->
  <a href="https://www.python.org/downloads/release/python-3080/"><img src="https://img.shields.io/badge/python-3.8-blue.svg"></a>
  <a href="https://pypi.org/project/pylibbpf"><img src="https://badge.fury.io/py/pylibbpf.svg"></a>
  <!-- <a href="https://pypi.org/project/pythonbpf/"><img src="https://img.shields.io/pypi/status/pythonbpf" alt="PyPI Status"></a> -->
  <a href="https://pepy.tech/project/pylibbpf"><img src="https://pepy.tech/badge/pylibbpf" alt="Downloads"></a>
  <!-- Build & CI -->
  <a href="https://github.com/pythonbpf/pylibbpf/actions"><img src="https://github.com/pythonbpf/pylibbpf/actions/workflows/wheels.yml/badge.svg" alt="Build Status"></a>
  <!-- Meta -->
  <a href="https://github.com/pythonbpf/pylibbpf/blob/master/LICENSE"><img src="https://img.shields.io/github/license/pythonbpf/pylibbpf" alt="License"></a>
</p>

This library provides Python bindings for **libbpf** on Linux, making it easier to load eBPF object files. It is designed to be used together with [PythonBPF](https://github.com/pythonbpf/python-bpf), the eBPF compiler for Python. With these bindings, you can attach eBPF programs to kernel events directly from Python.
All programs written with this are to be run with a `sudo` Python interpreter.

> **Note**: This project is under active development and not ready for production use.

## Dependencies

* A compiler with C++11 support
* Pip 10+ or CMake >= 4.1
* Ninja or Pip 10+

## Installation
`pip install pylibbpf`

## Development

Clone this repository and pip install. Note the `--recursive` option which is
needed for the pybind11 submodule:

```bash
sudo apt install libelf-dev
git clone --recursive https://github.com/varun-r-mallya/pylibbpf.git
pip install .
```

With the `setup.py` file included in this example, the `pip install` command will
invoke CMake and build the pybind11 module as specified in `CMakeLists.txt`.

## Building the documentation
The documentation here is still boilerplate.
