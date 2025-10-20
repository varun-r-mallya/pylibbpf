#ifndef PYLIBBPF_BPF_EXCEPTION_H
#define PYLIBBPF_BPF_EXCEPTION_H

#include <stdexcept>
#include <string>

class BpfException final : public std::runtime_error {
public:
  explicit BpfException(const std::string &message)
      : std::runtime_error(message) {}

  explicit BpfException(const char *message) : std::runtime_error(message) {}
};

#endif // PYLIBBPF_BPF_EXCEPTION_H
