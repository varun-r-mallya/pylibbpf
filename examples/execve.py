from pythonbpf import bpf, map, section, bpfglobal, BPF
from ctypes import c_void_p, c_int64, c_int32, c_uint64
from pythonbpf.helpers import ktime
from pythonbpf.maps import HashMap
import time

@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=1)


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int32:
    print("entered")
    print("multi constant support")
    return c_int32(0)


@bpf
@section("tracepoint/syscalls/sys_exit_execve")
def hello_again(ctx: c_void_p) -> c_int64:
    print("exited")
    key = 0
    tsp = last().lookup(key)
    print(tsp)
    ts = ktime()
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load_and_attach()
while True:
    print("running")
    time.sleep(1)
