// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "client.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>

#include <catch2/catch_test_macros.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <libtorrent/alert_types.hpp>
#pragma GCC diagnostic pop
#include <libtorrent/bencode.hpp>
#include <libtorrent/create_torrent.hpp>
#include <libtorrent/entry.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/stack_allocator.hpp>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots::bittorrent {

using namespace std::chrono_literals;

//! BitTorrentClient with protected methods exposed for test
class BitTorrentClientForTest : public BitTorrentClient {
  public:
    using BitTorrentClient::BitTorrentClient;
    using BitTorrentClient::handle_alert;
    using BitTorrentClient::load_file;
    using BitTorrentClient::process_alerts;
    using BitTorrentClient::request_save_resume_data;
    using BitTorrentClient::request_torrent_updates;
    using BitTorrentClient::save_file;

    lt::torrent_handle add_torrent(lt::add_torrent_params params) {
        return session_.add_torrent(std::move(params));
    }
};

class ClientThread {
  public:
    explicit ClientThread(BitTorrentClient& client)
        : thread_([&client]() { client.execution_loop(); }) {}
    ~ClientThread() {
        thread_.join();
    }

  private:
    std::thread thread_;
};

//! Generate test data for resume file content
//! \details https://github.com/arvidn/libtorrent/blob/RC_2_0/test/test_read_resume.cpp
static std::vector<char> test_resume_data() {
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

TEST_CASE("BitTorrentClient::load_file", "[silkworm][snapshot][bittorrent]") {
    TemporaryDirectory tmp_dir;
    const auto path = tmp_dir.path() / "test.resume";
    const auto resume_data = test_resume_data();
    BitTorrentClientForTest::save_file(path, resume_data);
    CHECK(BitTorrentClientForTest::load_file(path) == resume_data);
}

TEST_CASE("BitTorrentClient::BitTorrentClient", "[silkworm][snapshot][bittorrent]") {
    TemporaryDirectory tmp_dir;
    BitTorrentSettings settings;
    settings.repository_path = tmp_dir.path();

    SECTION("default settings") {
        CHECK_NOTHROW(BitTorrentClient{settings});
    }

    SECTION("one invalid magnet link") {
        BitTorrentClient client{settings};
        // The following magnet link has malformed URL format ("unsupported URL protocol")
        CHECK_THROWS_AS(client.add_magnet_uri("magnet::?xt=urn:btih:df09957d8a28af3bc5137478885a8003677ca878"), std::runtime_error);
    }

    SECTION("nonempty resume dir") {
        const auto resume_dir_path = settings.repository_path / BitTorrentClient::kResumeDirName;
        std::filesystem::create_directories(resume_dir_path);

        const auto ignored_file{resume_dir_path / "a.txt"};
        BitTorrentClientForTest::save_file(ignored_file, std::vector<char>{});

        const auto empty_resume_file{resume_dir_path / "a.resume"};
        BitTorrentClientForTest::save_file(empty_resume_file, std::vector<char>{});

        const auto valid_resume_file{resume_dir_path / "83112dec4bec180cff67e01d6345c88c3134fd26.resume"};
        std::vector<char> resume_data{test_resume_data()};
        BitTorrentClientForTest::save_file(valid_resume_file, resume_data);

        CHECK_NOTHROW(BitTorrentClient{settings});
    }
}

TEST_CASE("BitTorrentClient::add_info_hash", "[silkworm][snapshot][bittorrent]") {
    TemporaryDirectory tmp_dir;
    BitTorrentSettings settings;
    settings.repository_path = tmp_dir.path();
    static constexpr std::string_view kTrackerUrl{"udp://127.0.0.1:1337/announce"};

    SECTION("invalid info hash") {
        BitTorrentClient client{settings};
        client.add_info_hash("test.seg", "df09957d8a28af3bc5137478885a8003677ca8", {std::string{kTrackerUrl}});
        ClientThread client_thread{client};
        CHECK_NOTHROW(client.stop());
    }

    SECTION("valid info hash") {
        BitTorrentClient client{settings};
        client.add_info_hash("test.seg", "df09957d8a28af3bc5137478885a8003677ca878", {std::string{kTrackerUrl}});
        ClientThread client_thread{client};
        CHECK_NOTHROW(client.stop());
    }
}

TEST_CASE("BitTorrentClient::execute_loop", "[silkworm][snapshot][bittorrent]") {
    TemporaryDirectory tmp_dir;
    BitTorrentSettings settings;
    settings.repository_path = tmp_dir.path();

    SECTION("nonempty magnet file") {
        BitTorrentClient client{settings};
        client.add_magnet_uri("magnet:?xt=urn:btih:df09957d8a28af3bc5137478885a8003677ca878");
        ClientThread client_thread{client};
        CHECK_NOTHROW(client.stop());
    }
}

TEST_CASE("BitTorrentClient::stop", "[silkworm][snapshot][bittorrent]") {
    TemporaryDirectory tmp_dir;
    BitTorrentSettings settings;
    settings.repository_path = tmp_dir.path();

    SECTION("before starting") {
        BitTorrentClient client{settings};
        CHECK_NOTHROW(client.stop());
    }

    SECTION("after empty execution loop") {
        BitTorrentClient client{settings};
        ClientThread client_thread{client};
        CHECK_NOTHROW(client.stop());
    }
}

TEST_CASE("BitTorrentClient::request_torrent_updates", "[silkworm][snapshot][bittorrent]") {
    SECTION("trigger save resume data twice") {
        constexpr std::chrono::seconds kResumeDataSaveInterval{1};
        TemporaryDirectory tmp_dir;
        BitTorrentSettings settings;
        settings.repository_path = tmp_dir.path();
        settings.resume_data_save_interval = kResumeDataSaveInterval;
        BitTorrentClientForTest client{settings};
        CHECK_NOTHROW(client.request_torrent_updates(false));
        std::this_thread::sleep_for(kResumeDataSaveInterval);
        CHECK_NOTHROW(client.request_torrent_updates(false));
    }
}

TEST_CASE("BitTorrentClient::process_alerts", "[silkworm][snapshot][bittorrent]") {
    SECTION("one empty magnet link") {
        TemporaryDirectory tmp_dir;
        BitTorrentSettings settings;
        settings.repository_path = tmp_dir.path();
        BitTorrentClientForTest client{settings};
        // The following magnet link is empty
        client.add_magnet_uri("magnet:?xt=urn:btih:df09957d8a28af3bc5137478885a8003677ca878");
        CHECK_NOTHROW(client.process_alerts());
    }
}

TEST_CASE("BitTorrentClient::handle_alert", "[silkworm][snapshot][bittorrent]") {
    TemporaryDirectory tmp_dir;
    BitTorrentSettings settings;
    settings.repository_path = tmp_dir.path();
    BitTorrentClientForTest client{settings};
    lt::aux::stack_allocator allocator;
    lt::add_torrent_params params = lt::parse_magnet_uri("magnet:?xt=urn:btih:df09957d8a28af3bc5137478885a8003677ca878");
    params.save_path = settings.repository_path.string();
    lt::torrent_handle handle = client.add_torrent(params);

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
        lt::save_resume_data_alert alert{allocator, lt::add_torrent_params{params}, handle};
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
    SECTION("added_subscription is notified") {
        std::promise<std::filesystem::path> added_promise;
        auto handle_added = [&](const std::filesystem::path& added_path) {
            added_promise.set_value(added_path);
        };
        client.added_subscription.connect(handle_added);
        lt::error_code ec;
        lt::add_torrent_alert alert{allocator, handle, params, ec};
        REQUIRE(client.handle_alert(&alert));
        CHECK_NOTHROW(added_promise.get_future().get());
    }
    SECTION("stats_subscription is notified") {
        std::promise<lt::span<const int64_t>> stats_promise;
        auto handle_stats = [&](lt::span<const int64_t> counters) {
            stats_promise.set_value(counters);
        };
        client.stats_subscription.connect(handle_stats);
        lt::session_stats_alert alert{allocator, lt::counters{}};
        REQUIRE(client.handle_alert(&alert));
        CHECK_NOTHROW(stats_promise.get_future().get());
    }
    SECTION("completed_subscription is notified") {
        std::promise<std::filesystem::path> completed_promise;
        auto handle_completed = [&](const std::filesystem::path& added_path) {
            completed_promise.set_value(added_path);
        };
        client.completed_subscription.connect(handle_completed);
        lt::torrent_finished_alert alert{allocator, handle};
        REQUIRE(client.handle_alert(&alert));
        CHECK_NOTHROW(completed_promise.get_future().get());
    }
}

}  // namespace silkworm::snapshots::bittorrent
