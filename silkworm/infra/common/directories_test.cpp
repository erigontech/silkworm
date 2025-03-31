// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "directories.hpp"

#include <fstream>

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("DataDirectory::deploy") {
    {
        // Open and create a storage path
        TemporaryDirectory tmp_dir0;
        DataDirectory data_dir(/*base_path=*/tmp_dir0.path(), /*create=*/true);
        REQUIRE(data_dir.exists());
        REQUIRE_NOTHROW(data_dir.deploy());
        REQUIRE_THROWS(data_dir.clear());

        // Eventually delete the created paths
        std::filesystem::remove_all(data_dir.path());
        REQUIRE(data_dir.exists() == false);
    }
}

TEST_CASE("DataDirectory::from_chaindata") {
    TemporaryDirectory tmp_dir1;
    std::filesystem::path fake_path{tmp_dir1.path() / "nonexistentpath"};
    std::filesystem::path fake_path_root{fake_path.root_path()};
    REQUIRE_THROWS((void)DataDirectory::from_chaindata({}));                               // Can't be empty
    REQUIRE_THROWS((void)DataDirectory::from_chaindata(fake_path));                        // Does not exist
    REQUIRE_THROWS((void)DataDirectory::from_chaindata(fake_path_root));                   // Can't be root
    REQUIRE_THROWS((void)DataDirectory::from_chaindata(std::filesystem::current_path()));  // Can't be current path

    std::filesystem::create_directories(fake_path);
    REQUIRE_THROWS((void)DataDirectory::from_chaindata(fake_path));  // Not a valid chaindata path
    fake_path /= "chaindata";
    REQUIRE_THROWS((void)DataDirectory::from_chaindata(fake_path));  // Valid chaindata path but does not exist yet
    std::filesystem::create_directories(fake_path);
    REQUIRE_NOTHROW((void)DataDirectory::from_chaindata(fake_path));  // Valid chaindata path and exist

    {
        DataDirectory data_dir{DataDirectory::from_chaindata(fake_path)};
        REQUIRE_NOTHROW(data_dir.deploy());
        REQUIRE(data_dir.temp().is_empty());

        // Drop a file into etl temp
        {
            std::string filename{data_dir.temp().path().string() + "/fake.txt"};
            std::ofstream f(filename.c_str());
            f << "Some fake text" << std::flush;
            f.close();
        }
        std::filesystem::path etl_subpath{data_dir.temp().path() / "subdir"};
        std::filesystem::create_directories(etl_subpath);
        REQUIRE_FALSE(data_dir.temp().is_empty());
        REQUIRE(data_dir.temp().size() != 0);
        data_dir.temp().clear();
        REQUIRE(data_dir.temp().is_empty());
    }
}

}  // namespace silkworm
