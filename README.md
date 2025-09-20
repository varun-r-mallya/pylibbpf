# cmake_example for pybind11

An example [pybind11](https://github.com/pybind/pybind11) module built with a
CMake-based build system. This is useful for C++ codebases that have an
existing CMake project structure. This is being replaced by
[`scikit_build_example`](https://github.com/pybind/scikit_build_example), which uses
[scikit-build-core][], which is designed to allow Python
packages to be driven from CMake without depending on setuptools. The approach here has
some trade-offs not present in a pure setuptools build (see
[`python_example`](https://github.com/pybind/python_example)) or scikit-build-core. Python 3.7+ required;
see the commit history for older versions of Python.

Problems vs. scikit-build-core based example:

- You have to manually copy fixes/additions when they get added to this example (like when Apple Silicon support was added)
- Modern editable installs are not supported (scikit-build-core doesn't support them either yet, but probably will soon)
- You are depending on setuptools, which can and will change
- You are stuck with an all-or-nothing approach to adding cmake/ninja via wheels (scikit-build-core adds these only as needed, so it can be used on BSD, Cygwin, Pyodide, Android, etc)
- You are stuck with whatever CMake ships with (scikit-build-core backports FindPython for you)


## Prerequisites

* A compiler with C++11 support
* Pip 10+ or CMake >= 4.1
* Ninja or Pip 10+


## Installation

Just clone this repository and pip install. Note the `--recursive` option which is
needed for the pybind11 submodule:

```bash
git clone --recursive https://github.com/pybind/cmake_example.git
pip install ./cmake_example
```

With the `setup.py` file included in this example, the `pip install` command will
invoke CMake and build the pybind11 module as specified in `CMakeLists.txt`.



## Building the documentation

Documentation for the example project is generated using Sphinx. Sphinx has the
ability to automatically inspect the signatures and documentation strings in
the extension module to generate beautiful documentation in a variety formats.
The following command generates HTML-based reference documentation; for other
formats please refer to the Sphinx manual:

 - `cd cmake_example/docs`
 - `make html`


## License

Pybind11 is provided under a BSD-style license that can be found in the LICENSE
file. By using, distributing, or contributing to this project, you agree to the
terms and conditions of this license.


## Test call

```python
import cmake_example
cmake_example.add(1, 2)
```

[`cibuildwheel`]:    https://cibuildwheel.readthedocs.io
[scikit-build-core]: https://github.com/scikit-build/scikit-build-core
