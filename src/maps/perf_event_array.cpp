#include "perf_event_array.h"
#include "core/bpf_exception.h"

PerfEventArray::PerfEventArray(int map_fd, int page_cnt, py::function callback,
                             py::object lost_callback)
    : pb_(nullptr), callback_(std::move(callback)),
      lost_callback_(lost_callback) {

  if (page_cnt <= 0 || (page_cnt & (page_cnt - 1)) != 0) {
    throw BpfException("page_cnt must be a positive power of 2");
  }

  struct perf_buffer_opts pb_opts = {};
  pb_opts.sz = sizeof(pb_opts); // Required for forward compatibility

  pb_ = perf_buffer__new(
      map_fd, page_cnt,
      sample_callback_wrapper,                                   // sample_cb
      lost_callback.is_none() ? nullptr : lost_callback_wrapper, // lost_cb
      this,                                                      // ctx
      &pb_opts                                                   // opts
  );

  if (!pb_) {
    throw BpfException("Failed to create perf buffer: " +
                       std::string(std::strerror(errno)));
  }
}

PerfEventArray::~PerfEventArray() {
  if (pb_) {
    perf_buffer__free(pb_);
  }
}

void PerfEventArray::sample_callback_wrapper(void *ctx, int cpu, void *data,
                                            unsigned int size) {
  auto *self = static_cast<PerfEventArray *>(ctx);

  // Acquire GIL for Python calls
  py::gil_scoped_acquire acquire;

  try {
    // Convert data to Python bytes
    py::bytes py_data(static_cast<const char *>(data), size);

    // Call Python callback: callback(cpu, data, size)
    self->callback_(cpu, py_data, size);
  } catch (const py::error_already_set &e) {
    PyErr_Print();
  }
}

void PerfEventArray::lost_callback_wrapper(void *ctx, int cpu,
                                          unsigned long long cnt) {
  auto *self = static_cast<PerfEventArray *>(ctx);

  if (self->lost_callback_.is_none()) {
    return;
  }

  py::gil_scoped_acquire acquire;

  try {
    self->lost_callback_(cpu, cnt);
  } catch (const py::error_already_set &e) {
    PyErr_Print();
  }
}

int PerfEventArray::poll(int timeout_ms) {
  // Release GIL during blocking poll
  py::gil_scoped_release release;
  return perf_buffer__poll(pb_, timeout_ms);
}

int PerfEventArray::consume() {
  py::gil_scoped_release release;
  return perf_buffer__consume(pb_);
}
