import ctypes
import logging
from typing import Dict, Type

from llvmlite import ir

logger = logging.getLogger(__name__)


def ir_type_to_ctypes(ir_type):
    """Convert LLVM IR type to ctypes type."""
    if isinstance(ir_type, ir.IntType):
        width = ir_type.width
        type_map = {
            8: ctypes.c_uint8,
            16: ctypes.c_uint16,
            32: ctypes.c_uint32,
            64: ctypes.c_uint64,
        }
        if width not in type_map:
            raise ValueError(f"Unsupported integer width: {width}")
        return type_map[width]

    elif isinstance(ir_type, ir.ArrayType):
        count = ir_type.count
        element_type_ir = ir_type.element

        if isinstance(element_type_ir, ir.IntType) and element_type_ir.width == 8:
            # Use c_char for string fields (will have .decode())
            return ctypes.c_char * count
        else:
            element_type = ir_type_to_ctypes(element_type_ir)
            return element_type * count
    elif isinstance(ir_type, ir.PointerType):
        return ctypes.c_void_p

    else:
        raise TypeError(f"Unsupported IR type: {ir_type}")


def _make_repr(struct_name: str, fields: list):
    """Create a __repr__ function for a struct"""

    def __repr__(self):
        field_strs = []
        for field_name, _ in fields:
            value = getattr(self, field_name)
            field_strs.append(f"{field_name}={value}")
        return f"<{struct_name} {' '.join(field_strs)}>"

    return __repr__


def convert_structs_to_ctypes(structs_sym_tab) -> Dict[str, Type[ctypes.Structure]]:
    """Convert PythonBPF's structs_sym_tab to ctypes.Structure classes."""
    if not structs_sym_tab:
        return {}

    ctypes_structs = {}

    for struct_name, struct_type_obj in structs_sym_tab.items():
        try:
            fields = []
            for field_name, field_ir_type in struct_type_obj.fields.items():
                field_ctypes = ir_type_to_ctypes(field_ir_type)
                fields.append((field_name, field_ctypes))

            repr_func = _make_repr(struct_name, fields)

            struct_class = type(
                struct_name,
                (ctypes.Structure,),
                {
                    "_fields_": fields,
                    "__module__": "pylibbpf.ir_to_ctypes",
                    "__doc__": f"Auto-generated ctypes structure for {struct_name}",
                    "__repr__": repr_func,
                },
            )

            ctypes_structs[struct_name] = struct_class
            # Pretty print field info
            field_info = ", ".join(f"{name}: {typ.__name__}" for name, typ in fields)
            logger.debug(f"  {struct_name}({field_info})")
        except Exception as e:
            logger.error(f"Failed to convert struct '{struct_name}': {e}")
            raise
    logger.info(f"Converted struct '{struct_name}' to ctypes")
    return ctypes_structs


def is_pythonbpf_structs(structs) -> bool:
    """Check if structs dict is from PythonBPF."""
    if not isinstance(structs, dict) or not structs:
        return False

    first_value = next(iter(structs.values()))
    return (
        hasattr(first_value, "ir_type")
        and hasattr(first_value, "fields")
        and hasattr(first_value, "size")
    )


__all__ = ["convert_structs_to_ctypes", "is_pythonbpf_structs"]
