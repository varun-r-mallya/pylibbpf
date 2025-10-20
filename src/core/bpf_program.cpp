#include "core/bpf_program.h"
#include "core/bpf_exception.h"
#include "core/bpf_object.h"
#include <cerrno>
#include <cstring>
#include <utility>

BpfProgram::BpfProgram(std::shared_ptr<BpfObject> parent,
                       struct bpf_program *raw_prog,
                       const std::string &program_name)
    : parent_obj_(parent), prog_(raw_prog), link_(nullptr),
      program_name_(program_name) {
  if (!parent)
    throw BpfException("Parent BpfObject is null");
  if (!(parent->is_loaded()))
    throw BpfException("Parent BpfObject is not loaded");
  if (!raw_prog)
    throw BpfException("bpf_program pointer is null");
}

BpfProgram::~BpfProgram() { detach(); }

BpfProgram::BpfProgram(BpfProgram &&other) noexcept
    : parent_obj_(std::move(other.parent_obj_)), prog_(other.prog_),
      link_(other.link_), program_name_(std::move(other.program_name_)) {

  other.prog_ = nullptr;
  other.link_ = nullptr;
}

BpfProgram &BpfProgram::operator=(BpfProgram &&other) noexcept {
  if (this != &other) {
    detach();

    parent_obj_ = std::move(other.parent_obj_);
    prog_ = other.prog_;
    link_ = other.link_;
    program_name_ = std::move(other.program_name_);

    other.prog_ = nullptr;
    other.link_ = nullptr;
  }
  return *this;
}

void BpfProgram::attach() {
  // Check if parent is still alive
  auto parent = parent_obj_.lock();
  if (!parent) {
    throw BpfException("Parent BpfObject has been destroyed");
  }

  if (link_) {
    throw BpfException("Program '" + program_name_ + "' already attached");
  }

  if (!prog_) {
    throw BpfException("Program '" + program_name_ + "' not initialized");
  }

  link_ = bpf_program__attach(prog_);
  if (!link_) {
    std::string err_msg = "bpf_program__attach failed for program '" +
                          program_name_ + "': " + std::strerror(errno);
    throw BpfException(err_msg);
  }
}

void BpfProgram::detach() {
  if (link_) {
    bpf_link__destroy(link_);
    link_ = nullptr;
  }
}
