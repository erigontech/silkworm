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
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include <catch2/catch.hpp>

#include "data_dir.hpp"
#include "stopwatch.hpp"
#include "temp_dir.hpp"

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
    CHECK(sw1.laps().size() == 0);  // No more laps
    CHECK_FALSE(sw1);               // Not started

    CHECK(silkworm::StopWatch::format(918734032564785ns) == "10d 15h:12m:14.032s");
}

TEST_CASE("DataDirectory") {
    // Open and create default storage path
    DataDirectory data_dir{/*create = */ true};
    REQUIRE(data_dir.valid());
    REQUIRE_NOTHROW(data_dir.create_tree());

    // Eventually delete the created paths
    std::filesystem::remove_all(data_dir.get_base_path());

    TemporaryDirectory tmp_dir1;
    std::filesystem::path fake_path{std::filesystem::path(tmp_dir1.path()) / "nonexistentpath"};
    REQUIRE_THROWS((void)DataDirectory::from_chaindata(fake_path));  // Does not exist
    std::filesystem::create_directories(fake_path);
    REQUIRE_THROWS((void)DataDirectory::from_chaindata(fake_path));  // Not a valid chaindata path
    fake_path /= "erigon";
    fake_path /= "chaindata";
    REQUIRE_THROWS((void)DataDirectory::from_chaindata(fake_path));  // Valid chaindata path but does not exist yet
    std::filesystem::create_directories(fake_path);
    REQUIRE_NOTHROW((void)DataDirectory::from_chaindata(fake_path));  // Valid chaindata path and exist

    DataDirectory data_dir2{DataDirectory::from_chaindata(fake_path)};
    REQUIRE_NOTHROW(data_dir2.create_tree());

    auto etl_path{data_dir2.get_etl_path()};
    REQUIRE(std::filesystem::is_empty(etl_path));

    // Drop a file into etl temp
    {
        std::string filename{etl_path.string() + "/fake.txt"};
        std::ofstream f(filename.c_str());
    }

    REQUIRE(std::filesystem::is_empty(etl_path) == false);

    data_dir2.clear_etl_temp();
    REQUIRE(std::filesystem::is_empty(etl_path));
}

}  // namespace db
