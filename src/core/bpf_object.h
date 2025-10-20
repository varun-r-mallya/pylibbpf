#ifndef PYLIBBPF_BPF_OBJECT_H
#define PYLIBBPF_BPF_OBJECT_H

#include <libbpf.h>
#include <memory>
#include <pybind11/pybind11.h>
#include <string>
#include <unordered_map>

namespace py = pybind11;

class BpfProgram;
class BpfMap;
class StructParser;

/**
 * BpfObject - Represents a loaded BPF object file.
 *
 * This is the main entry point for loading BPF programs.
 * Owns the bpf_object* and manages all programs and maps within it.
 */
class BpfObject : public std::enable_shared_from_this<BpfObject> {
private:
  struct bpf_object *obj_;
  std::string object_path_;
  bool loaded_;

  mutable std::unordered_map<std::string, std::shared_ptr<BpfMap>> maps_cache_;
  mutable std::unordered_map<std::string, std::shared_ptr<BpfProgram>>
      prog_cache_;
  py::dict struct_defs_;
  mutable std::shared_ptr<StructParser> struct_parser_;

  std::shared_ptr<BpfProgram> _get_or_create_program(struct bpf_program *prog);
  std::shared_ptr<BpfMap> _get_or_create_map(struct bpf_map *map);

public:
  explicit BpfObject(std::string object_path, py::dict structs = py::dict());
  ~BpfObject();

  // Disable copy, allow move
  BpfObject(const BpfObject &) = delete;
  BpfObject &operator=(const BpfObject &) = delete;
  BpfObject(BpfObject &&) noexcept;
  BpfObject &operator=(BpfObject &&) noexcept;

  /**
   * Load the BPF object into the kernel.
   * Must be called before accessing programs or maps.
   */
  void load();

  /**
   * Check if object is loaded.
   */
  [[nodiscard]] bool is_loaded() const { return loaded_; }

  /**
   * Get the underlying bpf_object pointer.
   * Only for internal use by BpfProgram and BpfMap.
   */
  [[nodiscard]] struct bpf_object *get_obj() const { return obj_; }

  /**
   * Attach all programs in the object.
   */
  py::dict attach_all();

  // Program access
  [[nodiscard]] py::list get_program_names();
  [[nodiscard]] std::shared_ptr<BpfProgram>
  get_program(const std::string &name);
  [[nodiscard]] struct bpf_program *
  find_program_by_name(const std::string &name) const;
  [[nodiscard]] py::dict get_cached_programs() const;

  // Map access
  [[nodiscard]] py::list get_map_names();
  [[nodiscard]] std::shared_ptr<BpfMap> get_map(const std::string &name);
  [[nodiscard]] struct bpf_map *find_map_by_name(const std::string &name) const;
  [[nodiscard]] py::dict get_cached_maps() const;

  // Struct parsing
  [[nodiscard]] py::dict get_struct_defs() const { return struct_defs_; }
  [[nodiscard]] std::shared_ptr<StructParser> get_struct_parser() const;
};

#endif // PYLIBBPF_BPF_OBJECT_H
