#ifndef PYLIBBPF_PERF_EVENT_ARRAY_H
#define PYLIBBPF_PERF_EVENT_ARRAY_H

#include <libbpf.h>
#include <memory>
#include <pybind11/pybind11.h>
#include <string>

class StructParser;
class BpfMap;

namespace py = pybind11;

class PerfEventArray {
private:
  std::shared_ptr<BpfMap> map_;
  struct perf_buffer *pb_;
  py::function callback_;
  py::object lost_callback_;

  std::shared_ptr<StructParser> parser_;
  std::string struct_name_;

  // Static callback wrappers for C API
  static void sample_callback_wrapper(void *ctx, int cpu, void *data,
                                      unsigned int size);
  static void lost_callback_wrapper(void *ctx, int cpu, unsigned long long cnt);

public:
  PerfEventArray(std::shared_ptr<BpfMap> map, int page_cnt,
                 py::function callback, py::object lost_callback = py::none());
  PerfEventArray(std::shared_ptr<BpfMap> map, int page_cnt,
                 py::function callback, const std::string &struct_name,
                 py::object lost_callback = py::none());
  ~PerfEventArray();

  PerfEventArray(const PerfEventArray &) = delete;
  PerfEventArray &operator=(const PerfEventArray &) = delete;

  int poll(int timeout_ms);
  int consume();

  [[nodiscard]] std::shared_ptr<BpfMap> get_map() const { return map_; }
};

#endif // PYLIBBPF_PERF_EVENT_ARRAY_H
