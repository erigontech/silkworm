/*
   Copyright 2021 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#pragma once
#ifndef SILKWORM_COMMON_DATA_DIR_HPP_
#define SILKWORM_COMMON_DATA_DIR_HPP_

#include <filesystem>

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
    [[nodiscard]] bool exists() const;

    //! \brief Returns whether this Directory is uncontaminated (i.e. brand new with no contents)
    [[nodiscard]] bool is_pristine() const;

    //! \brief Returns the cumulative size of all contained files and subdirectories
    [[nodiscard]] size_t size() const;

    //! \brief Returns the std::filesystem::path of this Directory instance
    [[nodiscard]] const std::filesystem::path& path() const;

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
        : Directory(TemporaryDirectory::get_unique_temporary_path(base_path), true){};

    //! \brief Creates an instance of a TemporaryDirectory from OS temporary path
    explicit TemporaryDirectory() : Directory(TemporaryDirectory::get_unique_temporary_path(), true){};

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
//! A typical DataDirectory has at least 3 subdirs
//! <base_path>
//! ├───chaindata   <-- Where main database is stored
//! ├───etl-temp    <-- Where temporary files from etl collector are stored
//! └───nodes       <-- Where database(s) for discovered nodes are stored
class DataDirectory final : public Directory {
  public:
    //! \brief Creates an instance of Silkworm's data directory given an initial base path
    //! \param [in] base_path : the actual path of base directory
    //! \param [in] create : whether the directory itself and the underlying tree should be created
    explicit DataDirectory(const std::filesystem::path& base_path, bool create = false)
        : Directory(base_path, create),
          chaindata_(base_path / "chaindata", create),
          etl_(base_path / "etl-temp", create),
          nodes_(base_path / "nodes", create){};

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
    [[nodiscard]] const Directory& chaindata() const { return chaindata_; }
    //! \brief Returns the "etl" directory (where temporary etl files are stored)
    [[nodiscard]] const Directory& etl() const { return etl_; }
    //! \brief Returns the "nodes" directory (where discovery nodes info are stored)
    [[nodiscard]] const Directory& nodes() const { return nodes_; }

  private:
    Directory chaindata_;  // Database storage
    Directory etl_;        // Temporary etl files
    Directory nodes_;      // Nodes discovery databases
};

}  // namespace silkworm
#endif  // !SILKWORM_COMMON_DATA_DIR_HPP_
