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

#include "bittorrent.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>

#include <catch2/catch.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <libtorrent/alert_types.hpp>
#pragma GCC diagnostic pop
#include <libtorrent/bencode.hpp>
#include <libtorrent/create_torrent.hpp>
#include <libtorrent/entry.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/stack_allocator.hpp>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/test/log.hpp>

namespace silkworm {

using namespace std::chrono_literals;

//! BitTorrentClient with protected methods exposed for test
class BitTorrentClient_ForTest : public BitTorrentClient {
  public:
    using BitTorrentClient::BitTorrentClient;
    using BitTorrentClient::handle_alert;
    using BitTorrentClient::load_file;
    using BitTorrentClient::process_alerts;
    using BitTorrentClient::request_save_resume_data;
    using BitTorrentClient::request_torrent_updates;
    using BitTorrentClient::save_file;
};

//! Temporary repository for torrent files
class TestRepository {
  public:
    explicit TestRepository() = default;
    ~TestRepository() { magnet_file_stream_.close(); }

    std::filesystem::path path() const { return dir_.path(); }
    std::filesystem::path magnets_file_path() const { return magnets_file_path_; }

    void add_magnet(const std::string& magnet_link) { magnet_file_stream_ << magnet_link; }
    void flush() { magnet_file_stream_.flush(); }

  private:
    TemporaryDirectory dir_;
    std::filesystem::path magnets_file_path_{dir_.path() / "magnet_links"};
    std::ofstream magnet_file_stream_{magnets_file_path_};
};

//! Generate test data for resume file content
//! \details https://github.com/arvidn/libtorrent/blob/RC_2_0/test/test_read_resume.cpp
static inline std::vector<char> test_resume_data() {
    lt::entry rd;

    rd["file-format"] = "libtorrent resume file";
    rd["file-version"] = 1;
    rd["info-hash"] = "abcdefghijklmnopqrst";
    rd["pieces"] = "\x01\x01\x01\x01\x01\x01";

    rd["total_uploaded"] = 1337;
    rd["total_downloaded"] = 1338;
    rd["active_time"] = 1339;
    rd["seeding_time"] = 1340;
    rd["upload_rate_limit"] = 1343;
    rd["download_rate_limit"] = 1344;
    rd["max_connections"] = 1345;
    rd["max_uploads"] = 1346;
    rd["seed_mode"] = 0;
    rd["super_seeding"] = 0;
    rd["added_time"] = 1347;
    rd["completed_time"] = 1348;
    rd["finished_time"] = 1352;
    rd["last_seen_complete"] = 1353;

    rd["piece_priority"] = "\x01\x02\x03\x04\x05\x06";
    rd["auto_managed"] = 0;
    rd["sequential_download"] = 0;
    rd["paused"] = 0;

    std::vector<char> resume_data;
    lt::bencode(std::back_inserter(resume_data), rd);

    return resume_data;
}

TEST_CASE("BitTorrentSettings", "[silkworm][snapshot][bittorrent]") {
    BitTorrentSettings settings{};
    CHECK(settings.repository_path == BitTorrentSettings::kDefaultTorrentRepoPath);
    CHECK(settings.magnets_file_path == BitTorrentSettings::kDefaultMagnetsFilePath);
    CHECK(settings.wait_between_alert_polls == BitTorrentSettings::kDefaultWaitBetweenAlertPolls);
    CHECK(settings.resume_data_save_interval == BitTorrentSettings::kDefaultResumeDataSaveInterval);
    CHECK(settings.seeding == BitTorrentSettings::kDefaultSeeding);
    CHECK(settings.download_rate_limit == BitTorrentSettings::kDefaultDownloadRateLimit);
    CHECK(settings.upload_rate_limit == BitTorrentSettings::kDefaultUploadRateLimit);
    CHECK(settings.active_downloads == BitTorrentSettings::kDefaultActiveDownloads);
}

TEST_CASE("BitTorrentClient::BitTorrentClient", "[silkworm][snapshot][bittorrent]") {
    SECTION("default settings") {
        CHECK_NOTHROW(BitTorrentClient{BitTorrentSettings{}});
    }

    TestRepository repo;
    BitTorrentSettings settings{};
    settings.repository_path = repo.path().string();
    settings.magnets_file_path = repo.magnets_file_path().string();

    SECTION("one invalid magnet link") {
        // The following magnet link has malformed URL format ("unsupported URL protocol")
        repo.add_magnet("magnet::?xt=urn:btih:df09957d8a28af3bc5137478885a8003677ca878");
        repo.flush();
        CHECK_THROWS_AS(BitTorrentClient{settings}, std::runtime_error);
    }

    SECTION("nonempty resume dir") {
        const auto resume_dir_path = repo.path() / BitTorrentClient::kResumeDirName;
        std::filesystem::create_directories(resume_dir_path);
        const auto ignored_file{resume_dir_path / "a.txt"};
        BitTorrentClient_ForTest::save_file(ignored_file, std::vector<char>{});
        const auto empty_resume_file{resume_dir_path / "a.resume"};
        BitTorrentClient_ForTest::save_file(empty_resume_file, std::vector<char>{});
        const auto invalid_resume_file{resume_dir_path / "83112dec4bec180cff67e01d6345c88c3134fd26.resume"};
        std::vector<char> invalid_resume_data{};
        BitTorrentClient_ForTest::save_file(invalid_resume_file, invalid_resume_data);
        const auto valid_resume_file{resume_dir_path / "83112dec4bec180cff67e01d6345c88c3134fd26.resume"};
        std::vector<char> resume_data{test_resume_data()};
        BitTorrentClient_ForTest::save_file(valid_resume_file, resume_data);
        CHECK_NOTHROW(BitTorrentClient{settings});
    }
}

TEST_CASE("BitTorrentClient::execute_loop", "[silkworm][snapshot][bittorrent]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};

    TestRepository repo;
    BitTorrentSettings settings{};
    settings.repository_path = repo.path().string();
    settings.magnets_file_path = repo.magnets_file_path().string();

    SECTION("empty magnet file") {
        BitTorrentClient client{settings};
        CHECK_NOTHROW(client.execute_loop());
    }

    SECTION("empty magnet file on separate thread") {
        BitTorrentClient client{settings};
        std::thread{[&client]() { client.execute_loop(); }}.join();
    }

    SECTION("nonempty magnet file on separate thread") {
        repo.add_magnet("magnet:?xt=urn:btih:df09957d8a28af3bc5137478885a8003677ca878");
        repo.flush();
        BitTorrentClient client{settings};
        std::thread client_thread{[&client]() { client.execute_loop(); }};
        std::this_thread::sleep_for(50ms);
        CHECK_NOTHROW(client.stop());
        client_thread.join();
    }
}

TEST_CASE("BitTorrentClient::stop", "[silkworm][snapshot][bittorrent]") {
    TestRepository repo;
    BitTorrentSettings settings{};
    settings.repository_path = repo.path().string();
    settings.magnets_file_path = repo.magnets_file_path().string();

    SECTION("before starting") {
        BitTorrentClient client{settings};
        CHECK_NOTHROW(client.stop());
    }

    SECTION("after empty execution loop") {
        BitTorrentClient client{settings};
        client.execute_loop();
        CHECK_NOTHROW(client.stop());
    }

    SECTION("after empty execution loop on separate thread") {
        BitTorrentClient client{settings};
        std::thread execution_thread{[&client]() { client.execute_loop(); }};
        CHECK_NOTHROW(client.stop());
        execution_thread.join();
    }

    SECTION("interrupt seeding execution loop on separate thread") {
        settings.seeding = true;
        BitTorrentClient client{settings};
        std::thread execution_thread{[&client]() { client.execute_loop(); }};
        CHECK_NOTHROW(client.stop());
        execution_thread.join();
    }
}

TEST_CASE("BitTorrentClient::request_torrent_updates", "[silkworm][snapshot][bittorrent]") {
    SECTION("trigger save resume data twice") {
        constexpr std::chrono::seconds kResumeDataSaveInterval{1};
        TestRepository repo;
        BitTorrentSettings settings{};
        settings.repository_path = repo.path().string();
        settings.magnets_file_path = repo.magnets_file_path().string();
        settings.resume_data_save_interval = kResumeDataSaveInterval;
        BitTorrentClient_ForTest client{settings};
        CHECK_NOTHROW(client.request_torrent_updates());
        std::this_thread::sleep_for(kResumeDataSaveInterval);
        CHECK_NOTHROW(client.request_torrent_updates());
    }
}

TEST_CASE("BitTorrentClient::process_alerts", "[silkworm][snapshot][bittorrent]") {
    SECTION("one empty magnet link") {
        TestRepository repo;
        // The following magnet link is empty
        repo.add_magnet("magnet:?xt=urn:btih:df09957d8a28af3bc5137478885a8003677ca878");
        repo.flush();
        BitTorrentSettings settings{};
        settings.repository_path = repo.path().string();
        settings.magnets_file_path = repo.magnets_file_path().string();
        BitTorrentClient_ForTest client{settings};
        CHECK_NOTHROW(client.process_alerts());
    }
}

TEST_CASE("BitTorrentClient::handle_alert", "[silkworm][snapshot][bittorrent]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};

    TestRepository repo;
    BitTorrentSettings settings{};
    settings.repository_path = repo.path().string();
    settings.magnets_file_path = repo.magnets_file_path().string();
    BitTorrentClient_ForTest client{settings};
    lt::aux::stack_allocator allocator;
    lt::session session(lt::settings_pack{});
    lt::add_torrent_params params = lt::parse_magnet_uri("magnet:?xt=urn:btih:df09957d8a28af3bc5137478885a8003677ca878");
    params.save_path = "save_path";
    lt::torrent_handle handle = session.add_torrent(params);

    SECTION("lt::add_torrent_alert is handled") {
        lt::error_code ec;
        lt::add_torrent_alert alert{allocator, handle, params, ec};
        CHECK_NOTHROW(client.handle_alert(&alert));
    }
    SECTION("lt::torrent_finished_alert is handled") {
        lt::torrent_finished_alert alert{allocator, handle};
        CHECK_NOTHROW(client.handle_alert(&alert));
    }
    SECTION("lt::metadata_received_alert is handled") {
        lt::metadata_received_alert alert{allocator, handle};
        CHECK_NOTHROW(client.handle_alert(&alert));
    }
    SECTION("lt::save_resume_data_alert is handled") {
        lt::save_resume_data_alert alert{allocator, std::move(params), handle};
        CHECK_NOTHROW(client.handle_alert(&alert));
    }
    SECTION("lt::save_resume_data_failed_alert is handled") {
        lt::error_code ec;
        lt::save_resume_data_failed_alert alert{allocator, handle, ec};
        CHECK_NOTHROW(client.handle_alert(&alert));
    }
    SECTION("lt::state_update_alert is handled") {
        std::vector<lt::torrent_status> statuses;
        lt::state_update_alert alert{allocator, statuses};
        CHECK_NOTHROW(client.handle_alert(&alert));
    }
    SECTION("lt::performance_alert is handled") {
        lt::performance_alert alert{allocator, handle, lt::performance_alert::outstanding_request_limit_reached};
        CHECK_NOTHROW(client.handle_alert(&alert));
    }

    SECTION("other alerts are NOT handled") {
        lt::torrent_removed_alert alert1{allocator, handle, lt::info_hash_t{}, lt::client_data_t{}};
        CHECK_NOTHROW(!client.handle_alert(&alert1));
        lt::file_completed_alert alert2{allocator, handle, 1};
        CHECK_NOTHROW(!client.handle_alert(&alert2));
    }
}

}  // namespace silkworm
