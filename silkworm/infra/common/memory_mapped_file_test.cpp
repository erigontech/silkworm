/*
   Copyright 2022 The Silkworm Authors

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

#include "memory_mapped_file.hpp"

#include <chrono>
#include <fstream>
#include <stdexcept>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>

namespace silkworm {

using namespace std::chrono_literals;

TEST_CASE("MemoryMappedFile from file", "[silkworm][infra][common][memory_mapped_file]") {
    SECTION("constructor fails for nonexistent file") {
        CHECK_THROWS_AS(MemoryMappedFile{"nonexistent.txt"}, std::logic_error);
    }

    SECTION("constructor fails for existent empty file") {
        const auto tmp_file = TemporaryDirectory::get_unique_temporary_path();
        std::ofstream tmp_stream{tmp_file, std::ios_base::binary};
        tmp_stream.close();
        CHECK_THROWS_AS(MemoryMappedFile{tmp_file}, std::runtime_error);
    }

    SECTION("constructor succeeds for existent nonempty file") {
        const auto tmp_file = TemporaryDirectory::get_unique_temporary_path();
        std::ofstream tmp_stream{tmp_file, std::ios_base::binary};
        tmp_stream.write("\x01", 1);
        tmp_stream.close();
        CHECK_NOTHROW(MemoryMappedFile{tmp_file});
        CHECK_NOTHROW(MemoryMappedFile{tmp_file, {}, false});
        CHECK_NOTHROW(MemoryMappedFile{tmp_file.string()});
        CHECK_NOTHROW(MemoryMappedFile{tmp_file.string(), {}, false});
    }

    static constexpr std::string_view kFileContent{"\x01\x02\x03"};
    const auto tmp_file = TemporaryDirectory::get_unique_temporary_path();
    std::ofstream tmp_stream{tmp_file, std::ios_base::binary};
    tmp_stream.write(kFileContent.data(), static_cast<std::streamsize>(kFileContent.size()));
    tmp_stream.close();
    MemoryMappedFile mmf{tmp_file};

    SECTION("has expected memory address and size") {
        CHECK(mmf.region().data() != nullptr);
        CHECK(mmf.size() == kFileContent.size());
    }

    SECTION("has expected content") {
        const auto data{mmf.region().data()};
        CHECK(data[0] == '\x01');
        CHECK(data[1] == '\x02');
        CHECK(data[2] == '\x03');
    }

    SECTION("advise_sequential") {
        CHECK_NOTHROW(mmf.advise_sequential());
    }

    SECTION("advise_random") {
        CHECK_NOTHROW(mmf.advise_random());
    }

    SECTION("input stream") {
        MemoryMappedInputStream mmis{mmf.region()};
        std::string s;
        mmis >> s;
        CHECK(s == kFileContent);
    }

    SECTION("last_write_time") {
        const auto tmp_path = std::filesystem::temp_directory_path() / "example.bin";
        std::ofstream{tmp_path.c_str()}.put('a');
        MemoryMappedFile mm_file{tmp_path};
        const auto ftime = mm_file.last_write_time();
        // Move file write time 1 hour to the future
        std::filesystem::last_write_time(tmp_path, ftime + 1h);
        const auto new_ftime = mm_file.last_write_time();
        CHECK((new_ftime > ftime));
        std::filesystem::remove(tmp_path);
    }
}

TEST_CASE("MemoryMappedFile from memory", "[silkworm][infra][common][memory_mapped_file]") {
    SECTION("constructor fails for null address") {
        CHECK_THROWS_AS(MemoryMappedFile("", MemoryMappedRegion{}), std::logic_error);
    }

    SECTION("constructor fails for zero length") {
        uint8_t u{0};
        CHECK_THROWS_AS(MemoryMappedFile("", MemoryMappedRegion{&u, 0}), std::logic_error);
    }

    SECTION("constructor succeeds for existent nonempty file") {
        const auto tmp_file = TemporaryDirectory::get_unique_temporary_path();
        std::ofstream tmp_stream{tmp_file, std::ios_base::binary};
        tmp_stream.write("\x01", 1);
        tmp_stream.close();
        MemoryMappedFile mmf_from_file{tmp_file};
        CHECK_NOTHROW(MemoryMappedFile(tmp_file, mmf_from_file.region()));
    }

    static constexpr std::string_view kFileContent{"\x01\x02\x03"};
    const auto tmp_file = TemporaryDirectory::get_unique_temporary_path();
    std::ofstream tmp_stream{tmp_file, std::ios_base::binary};
    tmp_stream.write(kFileContent.data(), static_cast<std::streamsize>(kFileContent.size()));
    tmp_stream.close();
    MemoryMappedFile mmf_from_file{tmp_file};
    const auto region{mmf_from_file.region()};
    MemoryMappedFile mmf{tmp_file, mmf_from_file.region()};

    SECTION("has expected memory address and size") {
        CHECK(mmf.region().data() == region.data());
        CHECK(mmf.region().size() == region.size());
    }

    SECTION("has expected content") {
        const auto data{mmf.region().data()};
        CHECK(data[0] == '\x01');
        CHECK(data[1] == '\x02');
        CHECK(data[2] == '\x03');
    }

    SECTION("advise_sequential") {
        CHECK_NOTHROW(mmf.advise_sequential());
    }

    SECTION("advise_random") {
        CHECK_NOTHROW(mmf.advise_random());
    }

    SECTION("input stream") {
        MemoryMappedInputStream mmis{mmf.region()};
        std::string s;
        mmis >> s;
        CHECK(s == kFileContent);
    }

    SECTION("last_write_time") {
        const auto tmp_path = std::filesystem::temp_directory_path() / "example.bin";
        std::ofstream{tmp_path.c_str()}.put('a');
        MemoryMappedFile mmf_from_path{tmp_path};
        MemoryMappedFile mmf_from_memory{tmp_path, mmf_from_file.region()};
        const auto ftime = mmf_from_memory.last_write_time();
        // Move file write time 1 hour to the future
        std::filesystem::last_write_time(tmp_path, ftime + 1h);
        const auto new_ftime = mmf_from_memory.last_write_time();
        CHECK((new_ftime > ftime));
        std::filesystem::remove(tmp_path);
    }
}

}  // namespace silkworm
