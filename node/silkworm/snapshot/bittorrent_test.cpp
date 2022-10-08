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
#include <libtorrent/aux_/alert_manager.hpp>
#include <libtorrent/create_torrent.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/stack_allocator.hpp>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/test/log.hpp>

namespace silkworm {

class BitTorrentClient_ForTest : public BitTorrentClient {
  public:
    using BitTorrentClient::BitTorrentClient;
    using BitTorrentClient::handle_alert;
    using BitTorrentClient::process_alerts;
    using BitTorrentClient::request_save_resume_data;
    using BitTorrentClient::request_torrent_updates;
};

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

TEST_CASE("BitTorrentSettings", "[silkworm][snapshot][bittorrent]") {
    BitTorrentSettings settings{};
    CHECK(settings.repository_path == kDefaultTorrentRepoPath);
    CHECK(settings.magnets_file_path == kDefaultMagnetsFilePath);
    CHECK(settings.wait_between_alert_polls == kDefaultWaitBetweenAlertPolls);
    CHECK(settings.resume_data_save_interval == kDefaultResumeDataSaveInterval);
    CHECK(settings.seeding == kDefaultSeeding);
    CHECK(settings.download_rate_limit == kDefaultDownloadRateLimit);
    CHECK(settings.upload_rate_limit == kDefaultUploadRateLimit);
    CHECK(settings.active_downloads == kDefaultActiveDownloads);
}

TEST_CASE("BitTorrentClient::BitTorrentClient", "[silkworm][snapshot][bittorrent]") {
    SECTION("default settings") {
        CHECK_NOTHROW(BitTorrentClient{BitTorrentSettings{}});
    }

    SECTION("one invalid magnet link") {
        TestRepository repo;
        // The following magnet link has malformed URL format ("unsupported URL protocol")
        repo.add_magnet("magnet::?xt=urn:btih:df09957d8a28af3bc5137478885a8003677ca878");
        repo.flush();
        BitTorrentSettings settings{};
        settings.repository_path = repo.path();
        settings.magnets_file_path = repo.magnets_file_path();
        CHECK_THROWS_AS(BitTorrentClient{settings}, std::runtime_error);
    }
}

TEST_CASE("BitTorrentClient::execute_loop", "[silkworm][snapshot][bittorrent]") {
    TestRepository repo;
    BitTorrentSettings settings{};
    settings.repository_path = repo.path();
    settings.magnets_file_path = repo.magnets_file_path();

    SECTION("empty magnet file") {
        BitTorrentClient client{settings};
        CHECK_NOTHROW(client.execute_loop());
    }

    SECTION("empty magnet file on separate thread") {
        BitTorrentClient client{settings};
        std::thread{[&client]() { client.execute_loop(); }}.join();
    }
}

TEST_CASE("BitTorrentClient::stop", "[silkworm][snapshot][bittorrent]") {
    TestRepository repo;
    BitTorrentSettings settings{};
    settings.repository_path = repo.path();
    settings.magnets_file_path = repo.magnets_file_path();

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

TEST_CASE("BitTorrentClient::process_alerts", "[silkworm][snapshot][bittorrent]") {
    SECTION("one empty magnet link") {
        TestRepository repo;
        // The following magnet link is empty
        repo.add_magnet("magnet:?xt=urn:btih:df09957d8a28af3bc5137478885a8003677ca878");
        repo.flush();
        BitTorrentSettings settings{};
        settings.repository_path = repo.path();
        settings.magnets_file_path = repo.magnets_file_path();
        BitTorrentClient_ForTest client{settings};
        CHECK_NOTHROW(client.process_alerts());
    }
}

TEST_CASE("BitTorrentClient::handle_alert", "[silkworm][snapshot][bittorrent]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};

    TestRepository repo;
    BitTorrentSettings settings{};
    settings.repository_path = repo.path();
    settings.magnets_file_path = repo.magnets_file_path();
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
