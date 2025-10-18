#ifndef PYLIBBPF_BPF_MAP_H
#define PYLIBBPF_BPF_MAP_H

#include <libbpf.h>
#include <pybind11/pybind11.h>
#include <vector>
#include <string>

class BpfObject;

namespace py = pybind11;

class BpfMap {
private:
    std::weak_ptr<BpfObject> parent_obj_;
    struct bpf_map *map_;
    int map_fd_;
    std::string map_name_;

public:
    BpfMap(std::shared_ptr<BpfObject>, struct bpf_map *raw_map, const std::string &map_name);

    ~BpfMap() = default;

    [[nodiscard]] py::object lookup(const py::object &key) const;
    void update(const py::object &key, const py::object &value) const;
    void delete_elem(const py::object &key) const;
    py::list get_next_key(const py::object &key = py::none()) const;
    py::dict items() const;
    py::list keys() const;
    py::list values() const;

    [[nodiscard]] std::string get_name() const { return map_name_; }
    [[nodiscard]] int get_fd() const { return map_fd_; }
    [[nodiscard]] int get_type() const;
    [[nodiscard]] int get_key_size() const;
    [[nodiscard]] int get_value_size() const;
    [[nodiscard]] int get_max_entries() const;

private:
    static std::vector<uint8_t> python_to_bytes(const py::object &obj, size_t size);
    static py::object bytes_to_python(const std::vector<uint8_t> &data);
};

#endif //PYLIBBPF_MAPS_H
