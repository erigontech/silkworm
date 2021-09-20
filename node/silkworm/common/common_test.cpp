/*
   Copyright 2020-2021 The Silkworm Authors

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

#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

#include <catch2/catch.hpp>

#include "directories.hpp"
#include "stopwatch.hpp"

namespace db {
using namespace silkworm;

TEST_CASE("Stop Watch") {
    using namespace std::chrono_literals;
    silkworm::StopWatch sw1{};
    CHECK_FALSE(sw1);  // Not started

    auto [lap_time0, duration0] = sw1.lap();
    CHECK(duration0.count() == 0);
    CHECK(lap_time0 == silkworm::StopWatch::TimePoint());

    auto start_time = sw1.start();
    CHECK(sw1);  // Started

    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    auto [lap_time1, duration1] = sw1.lap();
    CHECK(duration1.count() >= 5 * 1000);
    CHECK(start_time < lap_time1);

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto [lap_time2, duration2] = sw1.lap();
    CHECK(duration2.count() >= 10 * 1000);
    CHECK(lap_time1 < lap_time2);

    auto duration3 = sw1.since_start(lap_time2);
    CHECK(duration3.count() == (duration1.count() + duration2.count()));

    CHECK(sw1.laps().size() == 3);  // Start + 2 laps
    for (auto& [t, _] : sw1.laps()) {
        CHECK(t >= start_time);
    }

    CHECK(sw1.format(duration3) != "");
    CHECK(sw1.format(918734032564785ns) == "10d 15h:12m:14.032s");
    CHECK(sw1.format(432034ms) == "7m:12.034s");
    CHECK(sw1.format(1ms) == "1ms");
    CHECK(sw1.format(1200ms) == "1.200s");
    CHECK(sw1.format(1200us) == "1.200ms");
    CHECK(sw1.format(200us) == "200us");

    sw1.reset();
    CHECK(sw1.laps().empty());  // No more laps
    CHECK_FALSE(sw1);           // Not started

    CHECK(silkworm::StopWatch::format(918734032564785ns) == "10d 15h:12m:14.032s");
}

TEST_CASE("DataDirectory") {
    {
        // Open and create default storage path
        DataDirectory data_dir{/*create = */ true};
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

}  // namespace db
