#include "maps/perf_event_array.h"
#include "core/bpf_exception.h"
#include "core/bpf_map.h"
#include "core/bpf_object.h"
#include "utils/struct_parser.h"
#include <cerrno>
#include <cstring>

PerfEventArray::PerfEventArray(std::shared_ptr<BpfMap> map, int page_cnt,
                               py::function callback, py::object lost_callback)
    : map_(map), pb_(nullptr), callback_(std::move(callback)),
      lost_callback_(std::move(lost_callback)) {

  if (map->get_type() != BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
    throw BpfException("Map '" + map->get_name() +
                       "' is not a PERF_EVENT_ARRAY");
  }

  if (page_cnt <= 0 || (page_cnt & (page_cnt - 1)) != 0) {
    throw BpfException("page_cnt must be a positive power of 2");
  }

  struct perf_buffer_opts pb_opts = {};
  pb_opts.sz = sizeof(pb_opts); // Required for forward compatibility

  pb_ = perf_buffer__new(
      map->get_fd(), page_cnt,
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

PerfEventArray::PerfEventArray(std::shared_ptr<BpfMap> map, int page_cnt,
                               py::function callback,
                               const std::string &struct_name,
                               py::object lost_callback)
    : PerfEventArray(map, page_cnt, callback, lost_callback) {

  auto parent = map->get_parent();
  if (!parent) {
    throw BpfException("Parent BpfObject has been destroyed");
  }

  parser_ = parent->get_struct_parser();
  struct_name_ = struct_name;

  if (!parser_) {
    throw BpfException("No struct definitions available");
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

    if (self->parser_ && !self->struct_name_.empty()) {
      py::object event = self->parser_->parse(self->struct_name_, py_data);
      self->callback_(cpu, event);
    } else {
      self->callback_(cpu, py_data);
    }

  } catch (const py::error_already_set &e) {
    PyErr_Print();
  } catch (const std::exception &e) {
    py::print("C++ error in perf callback:", e.what());
  }
}

void PerfEventArray::lost_callback_wrapper(void *ctx, int cpu,
                                           unsigned long long cnt) {
  auto *self = static_cast<PerfEventArray *>(ctx);

  py::gil_scoped_acquire acquire;

  try {
    if (!self->lost_callback_.is_none()) {
      py::function lost_fn = py::cast<py::function>(self->lost_callback_);
      lost_fn(cpu, cnt);
    } else {
      py::print("Lost", cnt, "events on CPU", cpu);
    }
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
