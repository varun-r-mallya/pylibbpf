#ifndef PYLIBBPF_BPF_PROGRAM_H
#define PYLIBBPF_BPF_PROGRAM_H

#include "libbpf.h"
#include <pybind11/stl.h>
#include <string>

namespace py = pybind11;

class BpfProgram {
private:
    struct bpf_object* obj_;
    struct bpf_program* prog_;
    struct bpf_link* link_;
    std::string object_path_;
    std::string program_name_;

public:
    explicit BpfProgram(const std::string& object_path, const std::string& program_name = "");
    ~BpfProgram();

    bool load();
    bool attach();

    bool is_loaded() const { return obj_ != nullptr; }
    bool is_attached() const { return link_ != nullptr; }
};

#endif //PYLIBBPF_BPF_PROGRAM_H
