// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "memory_mapped_file.hpp"

#include <chrono>
#include <fstream>
#include <stdexcept>

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

    const std::string file_content{"\x01\x02\x03"};
    const auto tmp_file = TemporaryDirectory::get_unique_temporary_path();
    std::ofstream tmp_stream{tmp_file, std::ios_base::binary};
    tmp_stream.write(file_content.data(), static_cast<std::streamsize>(file_content.size()));
    tmp_stream.close();
    MemoryMappedFile mmf{tmp_file};

    SECTION("has expected memory address and size") {
        CHECK(mmf.region().data() != nullptr);
        CHECK(mmf.size() == file_content.size());
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
        CHECK(s == file_content);
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

    const std::string file_content{"\x01\x02\x03"};
    const auto tmp_file = TemporaryDirectory::get_unique_temporary_path();
    std::ofstream tmp_stream{tmp_file, std::ios_base::binary};
    tmp_stream.write(file_content.data(), static_cast<std::streamsize>(file_content.size()));
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
        CHECK(s == file_content);
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
