#ifndef PYLIBBPF_BPF_PROGRAM_H
#define PYLIBBPF_BPF_PROGRAM_H

#include <libbpf.h>
#include <memory>
#include <string>

class BpfObject;

class BpfProgram {
private:
  std::weak_ptr<BpfObject> parent_obj_;
  struct bpf_program *prog_;
  struct bpf_link *link_;
  std::string program_name_;

public:
  explicit BpfProgram(std::shared_ptr<BpfObject> parent,
                      struct bpf_program *raw_prog,
                      const std::string &program_name);

  ~BpfProgram();

  BpfProgram(const BpfProgram &) = delete;
  BpfProgram &operator=(const BpfProgram &) = delete;
  BpfProgram(BpfProgram &&) noexcept;
  BpfProgram &operator=(BpfProgram &&) noexcept;

  void attach();
  void detach();

  [[nodiscard]] bool is_attached() const { return link_ != nullptr; }
  [[nodiscard]] std::string get_name() const { return program_name_; }
};

#endif // PYLIBBPF_BPF_PROGRAM_H
