from typing import Callable, Optional


class PerfEventArrayHelper:
    """Fluent wrapper for PERF_EVENT_ARRAY maps."""

    def __init__(self, bpf_map):
        self._map = bpf_map
        self._perf_buffer = None

    def open_perf_buffer(
        self,
        callback: Callable,
        struct_name: str = "",
        page_cnt: int = 8,
        lost_callback: Optional[Callable] = None,
    ):
        """Open perf buffer with auto-deserialization."""
        from .pylibbpf import PerfEventArray

        if struct_name:
            self._perf_buffer = PerfEventArray(
                self._map,
                page_cnt,
                callback,
                struct_name,
                lost_callback or (lambda cpu, cnt: None),
            )
        else:
            self._perf_buffer = PerfEventArray(
                self._map, page_cnt, callback, lost_callback or (lambda cpu, cnt: None)
            )

        return self

    def poll(self, timeout_ms: int = -1) -> int:
        if not self._perf_buffer:
            raise RuntimeError("Call open_perf_buffer() first")
        return self._perf_buffer.poll(timeout_ms)

    def consume(self) -> int:
        if not self._perf_buffer:
            raise RuntimeError("Call open_perf_buffer() first")
        return self._perf_buffer.consume()

    def __getattr__(self, name):
        return getattr(self._map, name)


class BpfObjectWrapper:
    """Smart wrapper that returns map-specific helpers."""

    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
    BPF_MAP_TYPE_RINGBUF = 27

    def __init__(self, bpf_object):
        self._obj = bpf_object
        self._map_helpers = {}

    def __getitem__(self, name: str):
        """Return appropriate helper based on map type."""
        if name in self._map_helpers:
            return self._map_helpers[name]

        map_obj = self._obj[name]
        map_type = map_obj.get_type()

        if map_type == self.BPF_MAP_TYPE_PERF_EVENT_ARRAY:
            helper = PerfEventArrayHelper(map_obj)
        else:
            helper = map_obj

        self._map_helpers[name] = helper
        return helper

    def __getattr__(self, name):
        return getattr(self._obj, name)
