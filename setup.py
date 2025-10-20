import os
import subprocess
import sys
from pathlib import Path

from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext

# Convert distutils Windows platform specifiers to CMake -A arguments
PLAT_TO_CMAKE = {
    "win32": "Win32",
    "win-amd64": "x64",
    "win-arm32": "ARM",
    "win-arm64": "ARM64",
}


# A CMakeExtension needs a sourcedir instead of a file list.
# The name must be the _single_ output extension from the CMake build.
# If you need multiple extensions, see scikit-build.
class CMakeExtension(Extension):
    def __init__(self, name: str, sourcedir: str = "") -> None:
        super().__init__(name, sources=[])
        self.sourcedir = os.fspath(Path(sourcedir).resolve())


class CMakeBuild(build_ext):
    def build_extension(self, ext: CMakeExtension) -> None:
        # Must be in this form due to bug in .resolve() only fixed in Python 3.10+
        ext_fullpath = Path.cwd() / self.get_ext_fullpath(ext.name)
        extdir = ext_fullpath.parent.resolve()

        # Using this requires trailing slash for auto-detection & inclusion of
        # auxiliary "native" libs

        debug = int(os.environ.get("DEBUG", 0)) if self.debug is None else self.debug
        cfg = "Debug" if debug else "Release"

        # CMake lets you override the generator - we need to check this.
        # Can be set with Conda-Build, for example.
        cmake_generator = os.environ.get("CMAKE_GENERATOR", "")

        # Set Python_EXECUTABLE instead if you use PYBIND11_FINDPYTHON
        # EXAMPLE_VERSION_INFO shows you how to pass a value into the C++ code
        # from Python.
        cmake_args = [
            f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={extdir}{os.sep}",
            f"-DPYTHON_EXECUTABLE={sys.executable}",
            f"-DCMAKE_BUILD_TYPE={cfg}",  # not used on MSVC, but no harm
        ]
        build_args = []

        # Adding CMake arguments set as environment variable
        # (needed e.g. to build for ARM OSx on conda-forge)
        if "CMAKE_ARGS" in os.environ:
            cmake_args += [item for item in os.environ["CMAKE_ARGS"].split(" ") if item]

        # Pass version to CMake
        cmake_args += [f"-DPYLIBBPF_VERSION_INFO={self.distribution.get_version()}"]

        # Linux-specific build configuration
        if sys.platform.startswith("linux"):
            # Using Ninja-build since it a) is available as a wheel and b)
            # multithreads automatically.
            if not cmake_generator or cmake_generator == "Ninja":
                try:
                    import ninja

                    ninja_executable_path = Path(ninja.BIN_DIR) / "ninja"
                    cmake_args += [
                        "-GNinja",
                        f"-DCMAKE_MAKE_PROGRAM:FILEPATH={ninja_executable_path}",
                    ]
                except ImportError:
                    pass

            # Handle cross-compilation for different architectures on Linux
            # This is useful for building ARM binaries on x86 systems or vice versa
            target_arch = os.environ.get("TARGET_ARCH", "")
            if target_arch:
                if target_arch in ["arm64", "aarch64"]:
                    cmake_args += [
                        "-DCMAKE_SYSTEM_PROCESSOR=aarch64",
                        "-DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc",
                        "-DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++",
                    ]
                elif target_arch in ["arm", "armv7l"]:
                    cmake_args += [
                        "-DCMAKE_SYSTEM_PROCESSOR=arm",
                        "-DCMAKE_C_COMPILER=arm-linux-gnueabihf-gcc",
                        "-DCMAKE_CXX_COMPILER=arm-linux-gnueabihf-g++",
                    ]

        elif not sys.platform.startswith("linux"):
            raise RuntimeError("pylibbpf is only supported on Linux platforms")

        # Set CMAKE_BUILD_PARALLEL_LEVEL to control the parallel build level
        # across all generators.
        if "CMAKE_BUILD_PARALLEL_LEVEL" not in os.environ:
            # self.parallel is a Python 3 only way to set parallel jobs by hand
            # using -j in the build_ext call, not supported by pip or PyPA-build.
            if hasattr(self, "parallel") and self.parallel:
                # CMake 3.12+ only.
                build_args += [f"-j{self.parallel}"]

        build_temp = Path(self.build_temp) / ext.name
        if not build_temp.exists():
            build_temp.mkdir(parents=True)

        subprocess.run(
            ["cmake", ext.sourcedir, *cmake_args], cwd=build_temp, check=True
        )
        subprocess.run(
            ["cmake", "--build", ".", *build_args], cwd=build_temp, check=True
        )


# Read long description from README
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")

setup(
    name="pylibbpf",
    version="0.0.1",
    author="varun-r-mallya, r41k0u",
    author_email="varunrmallyagmail.com",
    description="Python Bindings for Libbpf",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pythonbpf/pylibbpf",
    packages=find_packages(where="."),
    package_dir={"": "."},
    py_modules=[],  # Empty since we use packages
    ext_modules=[CMakeExtension("pylibbpf.pylibbpf")],
    cmdclass={"build_ext": CMakeBuild},
    zip_safe=False,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: C++",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Operating System Kernels :: Linux",
    ],
    install_requires=[
        "llvmlite>=0.40.0",  # Required for struct conversion
    ],
    extras_require={"test": ["pytest>=6.0"]},
    python_requires=">=3.8",
    package_data={
        "pylibbpf": [
            "*.py",
            "py.typed",  # For type hints
        ],
    },
    include_package_data=True,
)
