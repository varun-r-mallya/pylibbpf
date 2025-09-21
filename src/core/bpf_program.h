#ifndef PYLIBBPF_BPF_PROGRAM_H
#define PYLIBBPF_BPF_PROGRAM_H

#include <libbpf.h>
#include <pybind11/stl.h>
#include <string>

namespace py = pybind11;

class BpfProgram {
private:
    struct bpf_object *obj_;
    struct bpf_program *prog_;
    struct bpf_link *link_;
    std::string object_path_;
    std::string program_name_;
    std::vector<std::pair<bpf_program *, bpf_link *> > programs;

public:
    explicit BpfProgram(std::string object_path, std::string program_name = "");

    ~BpfProgram();

    struct bpf_object *get_obj() const;

    bool load();

    bool attach();

    bool destroy();

    void load_and_attach();

    [[nodiscard]] bool is_loaded() const { return obj_ != nullptr; }
    [[nodiscard]] bool is_attached() const { return link_ != nullptr; }
};

#endif //PYLIBBPF_BPF_PROGRAM_H
