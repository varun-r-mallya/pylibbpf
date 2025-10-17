#include "bpf_object.h"
#include "bpf_program.h"
#include "bpf_map.h"
#include "bpf_exception.h"
#include <cerrno>

BpfObject::BpfObject(std::string object_path)
    : obj_(nullptr), object_path_(std::move(object_path)), loaded_(false) {
}

BpfObject::~BpfObject() {
    // Clear caches first (order matters!)
    prog_cache_.clear();  // Detaches programs
    maps_cache_.clear();      // Closes maps
    
    // Then close object
    if (obj_) {
        bpf_object__close(obj_);
        obj_ = nullptr;
    }
}

BpfObject::BpfObject(BpfObject&& other) noexcept
    : obj_(other.obj_),
      object_path_(std::move(other.object_path_)),
      loaded_(other.loaded_),
      prog_cache_(std::move(other.prog_cache_)),
      maps_cache_(std::move(other.maps_cache_)) {
    
    other.obj_ = nullptr;
    other.loaded_ = false;
}

BpfObject& BpfObject::operator=(BpfObject&& other) noexcept {
    if (this != &other) {
        prog_cache_.clear();
        maps_cache_.clear();
        if (obj_) {
            bpf_object__close(obj_);
        }
        
        obj_ = other.obj_;
        object_path_ = std::move(other.object_path_);
        loaded_ = other.loaded_;
        prog_cache_ = std::move(other.prog_cache_);
        maps_cache_ = std::move(other.maps_cache_);
        
        other.obj_ = nullptr;
        other.loaded_ = false;
    }
    return *this;
}

void BpfObject::load() {
    if (loaded_) {
        throw BpfException("BPF object already loaded");
    }
    
    std::string error_msg = "Failed to open BPF object";
    obj_ = bpf_object__open_file(object_path_.c_str(), nullptr);

    if (!obj_) {
	error_msg += " file '" + object_path_ + "': " + std::strerror(errno);
	throw BpfException(error_msg);
    }
    
    if (bpf_object__load(obj_)) {
	std::string error_msg = " object from file '" + object_path_ + "': " + std::strerror(errno);
        bpf_object__close(obj_);
        obj_ = nullptr;
        throw BpfException(error_msg);
    }
    
    loaded_ = true;
}

// ==================== Program Methods ====================

py::list BpfObject::get_program_names() const {
    if (!loaded_) {
        throw BpfException("BPF object not loaded");
    }
    
    py::list names;
    struct bpf_program *prog = nullptr;
    
    bpf_object__for_each_program(prog, obj_) {
	_get_or_create_program(prog);  // Ensure cached
        names.append(bpf_program__name(prog));
    }
    
    return names;
}

std::shared_ptr<BpfProgram> BpfObject::_get_or_create_program(struct bpf_program *prog) {
    if (!prog) {
        throw BpfException("bpf_program pointer is null");
    }
    
    const char *name = bpf_program__name(prog);
    std::string prog_name(name ? name : "");
    
    // Check cache
    auto it = prog_cache_.find(prog_name);
    if (it != prog_cache_.end()) {
        return it->second;
    }
    
    // Create and cache
    auto bpf_prog = std::make_shared<BpfProgram>(this, prog, prog_name);
    prog_cache_[prog_name] = bpf_prog;
    
    return bpf_prog;
}

std::shared_ptr<BpfProgram> BpfObject::get_program(const std::string& name) {
    if (!loaded_) {
        throw BpfException("BPF object not loaded");
    }
    
    // Check cache
    auto it = prog_cache_.find(name);
    if (it != prog_cache_.end()) {
        return it->second;
    }
    
    // Create and cache
    struct bpf_program *raw_prog = find_program_by_name(name);
    auto prog = std::make_shared<BpfProgram>(this, raw_prog, name);
    prog_cache_[name] = prog;
    
    return prog;
}

struct bpf_program* BpfObject::find_program_by_name(const std::string& name) const {
    if (!loaded_) {
        throw BpfException("BPF object not loaded");
    }
    
    struct bpf_program *prog = bpf_object__find_program_by_name(obj_, name.c_str());
    if (!prog) {
        throw BpfException("Program '" + name + "' not found");
    }
    
    return prog;
}

py::dict BpfObject::get_cached_programs() const {
    py::dict programs;
    for (const auto& [name, prog] : prog_cache_) {
        programs[name] = prog;
    }
    return programs;
}

py::dict BpfObject::attach_all() {
    if (!loaded_) {
        throw BpfException("BPF object not loaded");
    }
    
    py::dict attached_programs;
    struct bpf_program *prog = nullptr;
    
    bpf_object__for_each_program(prog, obj_) {
	auto bpf_prog = _get_or_create_program(prog);
        
        if (!bpf_prog->is_attached()) {
            bpf_prog->attach();
        }
        
        const char *name = bpf_program__name(prog);
        attached_programs[name] = bpf_prog;
    }
    
    return attached_programs;
}

// ==================== Map Methods ====================

py::list BpfObject::get_map_names() const {
    if (!loaded_) {
        throw BpfException("BPF object not loaded");
    }
    
    py::list names;
    struct bpf_map *map = nullptr;
    
    bpf_object__for_each_map(map, obj_) {
	_get_or_create_map(map);  // Ensure cached
        names.append(bpf_map__name(map));
    }
    
    return names;
}

std::shared_ptr<BpfMap> BpfObject::get_map(const std::string& name) {
    if (!loaded_) {
        throw BpfException("BPF object not loaded");
    }
    
    // Check cache
    auto it = maps_cache_.find(name);
    if (it != maps_cache_.end()) {
        return it->second;
    }
    
    // Create and cache
    struct bpf_map *raw_map = find_map_by_name(name);
    auto map = std::make_shared<BpfMap>(this, raw_map, name);
    maps_cache_[name] = map;
    
    return map;
}

std::shared_ptr<BpfMap> BpfObject::_get_or_create_map(struct bpf_map *map) {
    if (!map) {
        throw BpfException("bpf_map pointer is null");
    }
    
    const char *name = bpf_map__name(map);
    std::string map_name(name ? name : "");
    
    // Check cache
    auto it = maps_cache_.find(map_name);
    if (it != maps_cache_.end()) {
        return it->second;
    }
    
    // Create and cache
    auto bpf_map = std::make_shared<BpfMap>(this, map, map_name);
    maps_cache_[map_name] = bpf_map;
    
    return bpf_map;
}

struct bpf_map* BpfObject::find_map_by_name(const std::string& name) const {
    if (!loaded_) {
        throw BpfException("BPF object not loaded");
    }
    
    struct bpf_map *map = bpf_object__find_map_by_name(obj_, name.c_str());
    if (!map) {
        throw BpfException("Map '" + name + "' not found");
    }
    
    return map;
}

py::dict BpfObject::get_cached_maps() const {
    py::dict maps;
    for (const auto& [name, map] : maps_cache_) {
        maps[name] = map;
    }
    return maps;
}
