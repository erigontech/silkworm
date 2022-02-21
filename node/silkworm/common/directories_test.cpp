/*
   Copyright 2020-2022 The Silkworm Authors

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

#include "directories.hpp"

#include <fstream>

#include <catch2/catch.hpp>

namespace silkworm {

TEST_CASE("DataDirectory") {
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

    {
        // Open datadir from current process running path
        DataDirectory data_dir{std::filesystem::path(), false};
        REQUIRE(data_dir.is_pristine() == false);
        REQUIRE(data_dir.exists() == true);
        REQUIRE_NOTHROW(data_dir.deploy());
    }

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
        REQUIRE(data_dir.etl().is_pristine());

        // Drop a file into etl temp
        {
            std::string filename{data_dir.etl().path().string() + "/fake.txt"};
            std::ofstream f(filename.c_str());
            f << "Some fake text" << std::flush;
            f.close();
        }
        std::filesystem::path etl_subpath{data_dir.etl().path() / "subdir"};
        std::filesystem::create_directories(etl_subpath);
        REQUIRE(data_dir.etl().is_pristine() == false);
        REQUIRE(data_dir.etl().size() != 0);
        data_dir.etl().clear();
        REQUIRE(data_dir.etl().is_pristine() == true);
    }
}

}  // namespace silkworm
