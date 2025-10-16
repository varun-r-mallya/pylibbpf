#include "bpf_perf_buffer.h"
#include "bpf_exception.h"

void BpfPerfBuffer::sample_callback_wrapper(void *ctx, int cpu, void *data, unsigned int size) {
    auto *self = static_cast<BpfPerfBuffer *>(ctx);
    
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

void BpfPerfBuffer::lost_callback_wrapper(void *ctx, int cpu, unsigned long long cnt) {
    auto *self = static_cast<BpfPerfBuffer *>(ctx);
    
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

BpfPerfBuffer::BpfPerfBuffer(int map_fd, int page_cnt, py::function callback, py::object lost_callback)
    : pb_(nullptr), callback_(std::move(callback)) {
    
    if (!lost_callback.is_none()) {
        lost_callback_ = lost_callback.cast<py::function>();
    }
    
    // Setup perf buffer options
    perf_buffer_opts pb_opts = {};
    pb_opts.sample_cb = sample_callback_wrapper;
    pb_opts.lost_cb = lost_callback.is_none() ? nullptr : lost_callback_wrapper;
    pb_opts.ctx = this;
    
    // Create perf buffer
    pb_ = perf_buffer__new(map_fd, page_cnt, &pb_opts);
    if (!pb_) {
        throw BpfException("Failed to create perf buffer");
    }
}

BpfPerfBuffer::~BpfPerfBuffer() {
    if (pb_) {
        perf_buffer__free(pb_);
    }
}

int BpfPerfBuffer::poll(int timeout_ms) {
    // Release GIL during blocking poll
    py::gil_scoped_release release;
    return perf_buffer__poll(pb_, timeout_ms);
}

int BpfPerfBuffer::consume() {
    py::gil_scoped_release release;
    return perf_buffer__consume(pb_);
}
