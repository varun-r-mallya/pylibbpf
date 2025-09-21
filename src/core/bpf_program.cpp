#include "bpf_program.h"
#include "bpf_exception.h"
#include <filesystem>

BpfProgram::BpfProgram(const std::string& object_path, const std::string& program_name)
    : obj_(nullptr), prog_(nullptr), link_(nullptr),
      object_path_(object_path), program_name_(program_name) {
}

BpfProgram::~BpfProgram() {
    //TODO: detach here as well
    if (obj_) {
        bpf_object__close(obj_);
    }
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
        // Use the first program if no name specified
        prog_ = bpf_object__next_program(obj_, nullptr);
        if (!prog_) {
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
    if (!prog_) {
        throw BpfException("Program not loaded");
    }

    link_ = bpf_program__attach(prog_);
    if (libbpf_get_error(link_)) {
        link_ = nullptr;
        throw BpfException("Failed to attach BPF program");
    }

    return true;
}
