import pylibbpf as m


def test_main():
    assert m.__version__ == "0.0.4"
    prog = m.BpfProgram("tests/execve2.o")
    print(prog)
