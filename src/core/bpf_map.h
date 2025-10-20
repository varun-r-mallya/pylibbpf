#ifndef PYLIBBPF_BPF_MAP_H
#define PYLIBBPF_BPF_MAP_H

#include <array>
#include <libbpf.h>
#include <pybind11/pybind11.h>
#include <span>
#include <string>
#include <vector>

class BpfObject;

namespace py = pybind11;

class BpfMap : public std::enable_shared_from_this<BpfMap> {
private:
  std::weak_ptr<BpfObject> parent_obj_;
  struct bpf_map *map_;
  int map_fd_;
  std::string map_name_;
  __u32 key_size_, value_size_;

  template <size_t StackSize = 64> struct BufferManager {
    std::array<uint8_t, StackSize> stack_buf;
    std::vector<uint8_t> heap_buf;

    std::span<uint8_t> get_span(size_t size) {
      if (size <= StackSize) {
        return std::span<uint8_t>(stack_buf.data(), size);
      } else {
        heap_buf.resize(size);
        return std::span<uint8_t>(heap_buf);
      }
    }
  };

public:
  BpfMap(std::shared_ptr<BpfObject> parent, struct bpf_map *raw_map,
         const std::string &map_name);

  ~BpfMap() = default;

  BpfMap(const BpfMap &) = delete;
  BpfMap &operator=(const BpfMap &) = delete;
  BpfMap(BpfMap &&) noexcept = default;
  BpfMap &operator=(BpfMap &&) noexcept = default;

  [[nodiscard]] py::object lookup(const py::object &key) const;
  void update(const py::object &key, const py::object &value) const;
  void delete_elem(const py::object &key) const;
  py::object get_next_key(const py::object &key = py::none()) const;
  py::dict items() const;
  py::list keys() const;
  py::list values() const;

  [[nodiscard]] std::string get_name() const { return map_name_; }
  [[nodiscard]] int get_fd() const { return map_fd_; }
  [[nodiscard]] int get_type() const;
  [[nodiscard]] int get_key_size() const { return key_size_; };
  [[nodiscard]] int get_value_size() const { return value_size_; };
  [[nodiscard]] int get_max_entries() const;
  [[nodiscard]] std::shared_ptr<BpfObject> get_parent() const {
    return parent_obj_.lock();
  }

private:
  static void python_to_bytes_inplace(const py::object &obj,
                                      std::span<uint8_t> buffer);
  static py::object bytes_to_python(std::span<const uint8_t> data);
};

#endif // PYLIBBPF_BPF_MAP_H
