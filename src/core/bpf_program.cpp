#include "bpf_program.h"
#include "bpf_exception.h"
#include <filesystem>
#include <utility>

BpfProgram::BpfProgram(std::string object_path, std::string program_name)
    : obj_(nullptr), prog_(nullptr), link_(nullptr),
      object_path_(std::move(object_path)), program_name_(std::move(program_name)) {
}

BpfProgram::~BpfProgram() {
    destroy();
    if (obj_) {
        bpf_object__close(obj_);
    }
}

struct bpf_object * BpfProgram::get_obj() const {
    return obj_;
}

bool BpfProgram::load() {
    // Open the eBPF object file
    obj_ = bpf_object__open_file(object_path_.c_str(), nullptr);
    if (libbpf_get_error(obj_)) {
        throw BpfException("Failed to open BPF object file: " + object_path_);
    }

    // Find the program by name (if specified)
    if (!program_name_.empty()) {
        prog_ = bpf_object__find_program_by_name(obj_, program_name_.c_str());
        if (!prog_) {
            throw BpfException("Program '" + program_name_ + "' not found in object");
        }
    } else {
        while ((prog_ = bpf_object__next_program(obj_, prog_)) != nullptr) {
            programs.emplace_back(prog_, nullptr);
        }

        // throw if no programs found
        if (programs.empty()) {
            throw BpfException("No programs found in object file");
        }
    }

    // Load the eBPF object into the kernel
    if (bpf_object__load(obj_)) {
        throw BpfException("Failed to load BPF object into kernel");
    }

    return true;
}

bool BpfProgram::attach() {
    for (auto [prog, link]: programs) {
        if (!prog) {
            throw BpfException("Program not loaded");
        }

        link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            link = nullptr;
            throw BpfException("Failed to attach BPF program");
        }
    }

    return true;
}

bool BpfProgram::destroy() {
    bool success = true;
    for (auto [prog, link]: programs) {
        if (!prog) {
            throw BpfException("Program not loaded");
        }
        success = success & bpf_link__destroy(link);
    }
    return success;
}

void BpfProgram::load_and_attach() {
    load();
    attach();
}
