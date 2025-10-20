#include "core/bpf_map.h"
#include "core/bpf_exception.h"
#include "core/bpf_object.h"
#include <algorithm>
#include <cerrno>
#include <cstring>

BpfMap::BpfMap(std::shared_ptr<BpfObject> parent, struct bpf_map *raw_map,
               const std::string &map_name)
    : parent_obj_(parent), map_(raw_map), map_fd_(-1), map_name_(map_name),
      key_size_(0), value_size_(0) {
  if (!parent)
    throw BpfException("Parent BpfObject is null");
  if (!(parent->is_loaded()))
    throw BpfException("Parent BpfObject is not loaded");
  if (!raw_map)
    throw BpfException("bpf_map pointer is null");

  map_fd_ = bpf_map__fd(map_);
  if (map_fd_ < 0)
    throw BpfException("Failed to get file descriptor for map '" + map_name_ +
                       "'");

  key_size_ = bpf_map__key_size(map_);
  value_size_ = bpf_map__value_size(map_);
}

py::object BpfMap::lookup(const py::object &key) const {
  if (map_fd_ < 0)
    throw BpfException("Map '" + map_name_ + "' is not initialized properly");

  BufferManager<> key_buf, value_buf;
  auto key_span = key_buf.get_span(key_size_);
  auto value_span = value_buf.get_span(value_size_);

  // Convert Python → bytes
  python_to_bytes_inplace(key, key_span);

  // The flags field here matters only when spin locks are used.
  // Skipping it for now.
  const int ret = bpf_map__lookup_elem(map_, key_span.data(), key_size_,
                                       value_span.data(), value_size_, BPF_ANY);
  if (ret < 0) {
    if (ret == -ENOENT)
      throw py::key_error("Key not found in map '" + map_name_ + "'");
    throw BpfException("Failed to lookup key in map '" + map_name_ +
                       "': " + std::strerror(-ret));
  }

  return bytes_to_python(value_span);
}

void BpfMap::update(const py::object &key, const py::object &value) const {
  if (map_fd_ < 0)
    throw BpfException("Map '" + map_name_ + "' is not initialized properly");

  BufferManager<> key_buf, value_buf;
  auto key_span = key_buf.get_span(key_size_);
  auto value_span = value_buf.get_span(value_size_);

  python_to_bytes_inplace(key, key_span);
  python_to_bytes_inplace(value, value_span);

  const int ret = bpf_map__update_elem(map_, key_span.data(), key_size_,
                                       value_span.data(), value_size_, BPF_ANY);
  if (ret < 0) {
    throw BpfException("Failed to update key in map '" + map_name_ +
                       "': " + std::strerror(-ret));
  }
}

void BpfMap::delete_elem(const py::object &key) const {
  if (map_fd_ < 0)
    throw BpfException("Map '" + map_name_ + "' is not initialized properly");

  BufferManager<> key_buf;
  auto key_span = key_buf.get_span(key_size_);

  // Convert Python → bytes
  python_to_bytes_inplace(key, key_span);

  const int ret =
      bpf_map__delete_elem(map_, key_span.data(), key_size_, BPF_ANY);

  if (ret != 0) {
    if (ret == -ENOENT)
      throw py::key_error("Key not found in map '" + map_name_ + "'");
    throw BpfException("Failed to delete key from map '" + map_name_ +
                       "': " + std::strerror(-ret));
  }
}

py::object BpfMap::get_next_key(const py::object &key) const {
  BufferManager<> next_key_buf;
  auto next_key = next_key_buf.get_span(key_size_);

  int ret;
  if (key.is_none()) {
    ret = bpf_map__get_next_key(map_, nullptr, next_key.data(), key_size_);
  } else {
    BufferManager<> key_buf;
    auto key_bytes = key_buf.get_span(key_size_);
    python_to_bytes_inplace(key, key_bytes);
    ret = bpf_map__get_next_key(map_, key_bytes.data(), next_key.data(),
                                key_size_);
  }

  if (ret < 0) {
    if (ret == -ENOENT) {
      // No more keys
      return py::none();
    }
    throw BpfException("Failed to get next key in map '" + map_name_ +
                       "': " + std::strerror(-ret));
  }

  return bytes_to_python(next_key);
}

py::dict BpfMap::items() const {
  py::dict result;

  py::object current_key = get_next_key(py::none());
  if (current_key.is_none()) {
    return result;
  }

  while (!current_key.is_none()) {
    try {
      py::object value = lookup(current_key);
      result[current_key] = value;
      current_key = get_next_key(current_key);
    } catch (const py::key_error &) {
      break;
    }
  }

  return result;
}

py::list BpfMap::keys() const {
  py::list result;

  py::object current_key = get_next_key(py::none());
  if (current_key.is_none()) {
    return result;
  }

  while (!current_key.is_none()) {
    result.append(current_key);
    current_key = get_next_key(current_key);
  }

  return result;
}

py::list BpfMap::values() const {
  py::list result;

  py::object current_key = get_next_key(py::none());
  if (current_key.is_none()) {
    return result;
  }

  while (!current_key.is_none()) {
    try {
      py::object value = lookup(current_key);
      result.append(value);
      current_key = get_next_key(current_key);
    } catch (const py::key_error &) {
      break;
    }
  }

  return result;
}

int BpfMap::get_type() const { return bpf_map__type(map_); }

int BpfMap::get_max_entries() const { return bpf_map__max_entries(map_); }

// Helper functions
void BpfMap::python_to_bytes_inplace(const py::object &obj,
                                     std::span<uint8_t> buffer) {
  std::fill(buffer.begin(), buffer.end(), 0);

  if (py::isinstance<py::int_>(obj)) {
    if (buffer.size() <= sizeof(uint64_t)) {
      uint64_t value = obj.cast<uint64_t>();
      std::memcpy(buffer.data(), &value, buffer.size());
    } else {
      throw BpfException("Integer key/value size exceeds maximum (8 bytes)");
    }
  } else if (py::isinstance<py::bytes>(obj)) {
    std::string bytes_str = obj.cast<std::string>();

    if (bytes_str.size() > buffer.size()) {
      throw BpfException("Bytes size " + std::to_string(bytes_str.size()) +
                         " exceeds expected size " +
                         std::to_string(buffer.size()));
    }

    std::memcpy(buffer.data(), bytes_str.data(), bytes_str.size());
  } else if (py::isinstance<py::str>(obj)) {
    std::string str_val = obj.cast<std::string>();

    if (str_val.size() >= buffer.size()) {
      throw BpfException("String size exceeds expected size");
    }

    std::memcpy(buffer.data(), str_val.data(), str_val.size());
    buffer[str_val.size()] = '\0';
  } else {
    throw BpfException("Unsupported type for BPF map key/value");
  }
}

py::object BpfMap::bytes_to_python(std::span<const uint8_t> data) {
  if (data.size() == 4) {
    uint32_t value;
    std::memcpy(&value, data.data(), 4);
    return py::cast(value);
  } else if (data.size() == 8) {
    uint64_t value;
    std::memcpy(&value, data.data(), 8);
    return py::cast(value);
  } else {
    return py::bytes(reinterpret_cast<const char *>(data.data()), data.size());
  }
}
