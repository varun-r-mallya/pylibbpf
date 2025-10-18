#ifndef PYLIBBPF_BPF_PERF_BUFFER_H
#define PYLIBBPF_BPF_PERF_BUFFER_H

#include <libbpf.h>
#include <pybind11/functional.h>
#include <pybind11/pybind11.h>

namespace py = pybind11;

class BpfPerfBuffer {
private:
  struct perf_buffer *pb_;
  py::function callback_;
  py::function lost_callback_;

  // Static callback wrappers for C API
  static void sample_callback_wrapper(void *ctx, int cpu, void *data,
                                      unsigned int size);
  static void lost_callback_wrapper(void *ctx, int cpu, unsigned long long cnt);

public:
  BpfPerfBuffer(int map_fd, int page_cnt, py::function callback,
                py::object lost_callback = py::none());
  ~BpfPerfBuffer();

  int poll(int timeout_ms);
  int consume();
  [[nodiscard]] int fd() const;
};

#endif // PYLIBBPF_BPF_PERF_BUFFER_H
