// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <stdexcept>

namespace silkworm {

//! \brief Directory class acts as a wrapper around common functions and properties of a filesystem directory object
class Directory {
  public:
    //! Creates an instance of a Directory object provided the path
    //! \param [in] directory_path : the path of the directory
    //! \param [in] must_create : whether the directory must be created on filesystem should not exist
    explicit Directory(const std::filesystem::path& directory_path, bool must_create = false);
    virtual ~Directory() = default;

    // Not copyable nor movable
    Directory(const Directory&) = delete;
    Directory& operator=(const Directory&) = delete;

    //! \brief Returns whether this Directory exists on filesystem
    bool exists() const;

    //! \brief Returns whether this Directory is empty
    bool is_empty() const;

    //! \brief Returns the cumulative size of all contained files and subdirectories
    size_t size() const;

    //! \brief Returns the std::filesystem::path of this Directory instance
    const std::filesystem::path& path() const;

    //! \brief Removes all contained files and subdirectories
    virtual void clear() const;

    //! \brief Creates the directory on filesystem should not exist
    void create();

  protected:
    std::filesystem::path path_;
};

//! \brief TemporaryDirectory is a Directory which is automatically deleted on destructor of the instance.
//! The full path of the directory starts from a given path plus the discovery of a unique non-existent sub-path
//! through a linear search. Should no initial path be given, TemporaryDirectory is built from the path indicated
//! for temporary files storage by host OS environment variables
class TemporaryDirectory final : public Directory {
  public:
    //! \brief Creates an instance of a TemporaryDirectory from a user provided path
    //! \param [in] base_path :  A path where to append this instance to
    explicit TemporaryDirectory(const std::filesystem::path& base_path)
        : Directory(TemporaryDirectory::get_unique_temporary_path(base_path), true) {}

    //! \brief Creates an instance of a TemporaryDirectory from OS temporary path
    explicit TemporaryDirectory() : Directory(TemporaryDirectory::get_unique_temporary_path(), true) {}

    ~TemporaryDirectory() final {
        Directory::clear();
        std::filesystem::remove_all(path_);
    }

    //! \brief Returns the path to OS provided temporary storage location
    static std::filesystem::path get_os_temporary_path();
    //! \brief Builds a temporary path from OS provided temporary storage location
    static std::filesystem::path get_unique_temporary_path();
    //! \brief Builds a temporary path from user provided temporary storage location
    static std::filesystem::path get_unique_temporary_path(const std::filesystem::path& base_path);
};

//! \brief DataDirectory wraps the directory tree used by Silkworm as base storage path.
//! A typical DataDirectory has at least the following subdirs
//! <base_path>
//! ├───chaindata   <-- Where main database is stored
//! ├───temp        <-- Where temporary files are stored (e.g. from etl collector)
//! ├───nodes       <-- Where database(s) for discovered nodes are stored
//! └───snapshots   <-- Where snapshot files for blocks/transactions/... are stored
class DataDirectory final : public Directory {
  public:
    //! \brief Creates an instance of Silkworm's data directory given an initial base path
    //! \param [in] base_path : the actual path of base directory
    //! \param [in] create : whether the directory itself and the underlying tree should be created
    explicit DataDirectory(const std::filesystem::path& base_path, bool create = false)
        : Directory(base_path, create),
          chaindata_(base_path / "chaindata", create),
          forks_(base_path / "forks", create),
          logs_(base_path / "logs", create),
          nodes_(base_path / "nodes", create),
          snapshots_(base_path / "snapshots", create),
          temp_(base_path / "temp", create) {}

    //! \brief Creates an instance of Silkworm's data directory starting from default storage path. (each host OS has
    //! its own)
    //! \param [in] create : whether the directory itself and the underlying tree should be created
    explicit DataDirectory(bool create = false)
        : DataDirectory::DataDirectory(DataDirectory::get_default_storage_path(), create) {}

    //! \brief Creates an instance of Silkworm's data directory given an initial base path
    //! \param [in] base_path : a char ptr to base path definition
    //! \param [in] create : whether the directory itself and the underlying tree should be created
    explicit DataDirectory(const char* base_path, bool create = false)
        : DataDirectory::DataDirectory(std::filesystem::path(base_path), create) {}

    ~DataDirectory() final = default;

    // Not copyable nor movable
    DataDirectory(const DataDirectory&) = delete;
    DataDirectory& operator=(const DataDirectory&) = delete;

    //! \brief Returns an instance of Silkworm's data directory given an initial chaindata path
    //! \param chaindata_path
    //! \return a DataDirectory object
    static DataDirectory from_chaindata(const std::filesystem::path& chaindata_path);

    //! \brief Returns the path for default storage as defined by host OS environment variable(s)
    //! \return std::filesystem::path object
    static std::filesystem::path get_default_storage_path();

    //! \brief Deploys the full tree on filesystem (i.e. missing directories are created).
    //! Etl directory gets also cleared
    void deploy();

    //! \brief DataDirectory can't be cleared
    void clear() const final { throw std::runtime_error("Can't clear a DataDirectory"); }

    //! \brief Returns the "chaindata" directory (where chain database is stored)
    const Directory& chaindata() const { return chaindata_; }
    //! \brief Returns the "forks" directory (where forks files are stored)
    const Directory& forks() const { return forks_; }
    //! \brief Returns the "logs" directory (where log files are stored)
    const Directory& logs() const { return logs_; }
    //! \brief Returns the "nodes" directory (where discovery nodes info are stored)
    const Directory& nodes() const { return nodes_; }
    //! \brief Returns the "snapshots" directory (where snapshot files are stored)
    const Directory& snapshots() const { return snapshots_; }
    //! \brief Returns the "temp" directory (where temporary files are stored)
    const Directory& temp() const { return temp_; }

  private:
    Directory chaindata_;  // Database storage
    Directory forks_;      // Fork files
    Directory logs_;       // Log files
    Directory nodes_;      // Nodes discovery databases
    Directory snapshots_;  // Snapshot files
    Directory temp_;       // Temporary etl files
};

}  // namespace silkworm
