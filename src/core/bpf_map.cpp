#include "bpf_map.h"

#include "bpf_exception.h"

BpfMap::BpfMap(BpfProgram *program_, const py::object &map_from_python) {
    if (py::isinstance<py::function>(map_from_python)) {
        const auto name = map_from_python.attr("__name__").cast<std::string>();
        bpf_program = program_;
        map_ = bpf_object__find_map_by_name(bpf_program->get_obj(), name.c_str());
        if (!map_) {
            throw BpfException("Failed to find map by name");
        }
        map_fd = bpf_map__fd(map_);
        if (map_fd == -1) {
            throw BpfException("Failed to open map File Descriptor");
        }
    } else {
        throw BpfException("Invalid map object passed to function.");
    }
}

std::vector<uint8_t> BpfMap::python_to_bytes(const py::object &obj, size_t size) {
    std::vector<uint8_t> result(size, 0);

    if (py::isinstance<py::int_>(obj)) {
        const auto value = obj.cast<uint64_t>();
        std::memcpy(result.data(), &value, std::min(size, sizeof(uint64_t)));
    } else if (py::isinstance<py::bytes>(obj)) {
        const auto bytes_str = obj.cast<std::string>();
        std::memcpy(result.data(), bytes_str.data(), std::min(size, bytes_str.size()));
    } else if (py::isinstance<py::str>(obj)) {
        const auto str_val = obj.cast<std::string>();
        std::memcpy(result.data(), str_val.data(), std::min(size, str_val.size()));
    }

    return result;
}

py::object BpfMap::bytes_to_python(const std::vector<uint8_t> &data) {
    // Try to interpret as integer if it's a common integer size
    if (data.size() == 4) {
        uint32_t value;
        std::memcpy(&value, data.data(), 4);
        return py::cast(value);
    } else if (data.size() == 8) {
        uint64_t value;
        std::memcpy(&value, data.data(), 8);
        return py::cast(value);
    } else {
        // Return as bytes
        return py::bytes(reinterpret_cast<const char *>(data.data()), data.size());
    }
}

void BpfMap::update(const py::object &key, const py::object &value) const {
    const size_t key_size = bpf_map__key_size(map_);
    const size_t value_size = bpf_map__value_size(map_);

    const auto key_bytes = python_to_bytes(key, key_size);
    const auto value_bytes = python_to_bytes(value, value_size);

    const int ret = bpf_map__update_elem(
        map_,
        key_bytes.data(),
        key_size,
        value_bytes.data(),
        value_size,
        BPF_ANY);
    if (ret != 0) {
        throw BpfException("Failed to update map element");
    }
}

void BpfMap::delete_elem(const py::object &key) const {
    const size_t key_size = bpf_map__key_size(map_);
    std::vector<uint8_t> key_bytes;
    key_bytes = python_to_bytes(key, key_size);

    if (const int ret = bpf_map__delete_elem(map_, key_bytes.data(), key_size, BPF_ANY); ret != 0) {
        throw BpfException("Failed to delete map element");
    }
}

py::list BpfMap::get_next_key(const py::object &key) const {
    const size_t key_size = bpf_map__key_size(map_);
    std::vector<uint8_t> next_key(key_size);

    int ret;
    if (key.is_none()) {
        ret = bpf_map__get_next_key(map_, nullptr, next_key.data(), key_size);
    } else {
        const auto key_bytes = python_to_bytes(key, key_size);
        ret = bpf_map__get_next_key(map_, key_bytes.data(), next_key.data(), key_size);
    }

    py::list result;
    if (ret == 0) {
        result.append(bytes_to_python(next_key));
    }
    return result;
}

py::list BpfMap::keys() const {
    py::list result;
    const size_t key_size = bpf_map__key_size(map_);

    std::vector<uint8_t> key(key_size);
    std::vector<uint8_t> next_key(key_size);

    int ret = bpf_map__get_next_key(map_, nullptr, key.data(), key_size);

    while (ret == 0) {
        result.append(bytes_to_python(key));
        ret = bpf_map__get_next_key(map_, key.data(), next_key.data(), key_size);
        key = next_key;
    }

    return result;
}

py::list BpfMap::values() const {
    py::list result;
    const size_t key_size = bpf_map__key_size(map_);
    const size_t value_size = bpf_map__value_size(map_);

    std::vector<uint8_t> key(key_size);
    std::vector<uint8_t> next_key(key_size);
    std::vector<uint8_t> value(value_size);

    int ret = bpf_map__get_next_key(map_, nullptr, key.data(), key_size);

    while (ret == 0) {
        if (bpf_map__lookup_elem(map_, key.data(), key_size, value.data(), value_size, BPF_ANY) == 0) {
            result.append(bytes_to_python(value));
        }
        ret = bpf_map__get_next_key(map_, key.data(), next_key.data(), key_size);
        key = next_key;
    }

    return result;
}

std::string BpfMap::get_name() const {
    const char *name = bpf_map__name(map_);
    return name ? std::string(name) : "";
}

int BpfMap::get_type() const {
    return bpf_map__type(map_);
}

int BpfMap::get_key_size() const {
    return bpf_map__key_size(map_);
}

int BpfMap::get_value_size() const {
    return bpf_map__value_size(map_);
}

int BpfMap::get_max_entries() const {
    return bpf_map__max_entries(map_);
}

py::dict BpfMap::items() const {
    py::dict result;
    const size_t key_size = bpf_map__key_size(map_);
    const size_t value_size = bpf_map__value_size(map_);

    std::vector<uint8_t> key(key_size);
    std::vector<uint8_t> next_key(key_size);
    std::vector<uint8_t> value(value_size);

    // Get first key
    int ret = bpf_map__get_next_key(map_, nullptr, key.data(), key_size);

    while (ret == 0) {
        // Lookup value for current key
        if (bpf_map__lookup_elem(map_, key.data(), key_size, value.data(), value_size, BPF_ANY) == 0) {
            result[bytes_to_python(key)] = bytes_to_python(value);
        }

        // Get next key
        ret = bpf_map__get_next_key(map_, key.data(), next_key.data(), key_size);
        key = next_key;
    }

    return result;
}

py::object BpfMap::lookup(const py::object &key) const {
    const __u32 key_size = bpf_map__key_size(map_);
    const __u32 value_size = bpf_map__value_size(map_);

    const auto key_bytes = python_to_bytes(key, key_size);
    std::vector<uint8_t> value_bytes(value_size);

    // The flags field here matters only when spin locks are used which is close to fucking never, so fuck no,
    // im not adding it
    const int ret = bpf_map__lookup_elem(
        map_,
        key_bytes.data(),
        key_size,
        value_bytes.data(),
        value_size,
        BPF_ANY);
    if (ret != 0) {
        return py::none();
    }

    return bytes_to_python(value_bytes);
}
