#ifndef PYLIBBPF_MAPS_H
#define PYLIBBPF_MAPS_H

#include <libbpf.h>
#include <pybind11/pybind11.h>
#include <vector>
#include <string>

#include "bpf_program.h"

namespace py = pybind11;

class BpfMap {
private:
    struct bpf_map *map_;
    int map_fd = -1;
    //TODO: turn below into a shared pointer and ref count it so that there is no resource leakage
    BpfProgram *bpf_program;

public:
    BpfMap(BpfProgram *program_, const py::object &map_from_python);

    ~BpfMap() = default;

    [[nodiscard]] py::object lookup(const py::object &key) const;

    void update(const py::object &key, const py::object &value) const;

    void delete_elem(const py::object &key) const;

    py::list get_next_key(const py::object &key = py::none()) const;

    py::dict items() const;

    py::list keys() const;

    py::list values() const;

    [[nodiscard]] std::string get_name() const;

    int get_type() const;

    int get_key_size() const;

    int get_value_size() const;

    int get_max_entries() const;

private:
    static std::vector<uint8_t> python_to_bytes(const py::object &obj, size_t size);

    static py::object bytes_to_python(const std::vector<uint8_t> &data);
};

#endif //PYLIBBPF_MAPS_H
