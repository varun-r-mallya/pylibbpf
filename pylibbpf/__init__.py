import logging

from .ir_to_ctypes import convert_structs_to_ctypes, is_pythonbpf_structs
from .pylibbpf import (
    BpfException,
    BpfMap,
    BpfProgram,
    PerfEventArray,
    StructParser,
)
from .pylibbpf import (
    BpfObject as _BpfObject,  # C++ object (internal)
)
from .wrappers import BpfObjectWrapper

logger = logging.getLogger(__name__)


class BpfObject(BpfObjectWrapper):
    """BpfObject with automatic struct conversion"""

    def __init__(self, object_path: str, structs=None):
        """Create a BPF object"""
        if structs is None:
            structs = {}
        elif is_pythonbpf_structs(structs):
            logger.info(f"Auto-converting {len(structs)} PythonBPF structs to ctypes")
            structs = convert_structs_to_ctypes(structs)

        # Create C++ BpfObject with converted structs
        cpp_obj = _BpfObject(object_path, structs)

        # Initialize wrapper
        super().__init__(cpp_obj)


__all__ = [
    "BpfObject",
    "BpfProgram",
    "BpfMap",
    "PerfEventArray",
    "StructParser",
    "BpfException",
]

__version__ = "0.0.6"
