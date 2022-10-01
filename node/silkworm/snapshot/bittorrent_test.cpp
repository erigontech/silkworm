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
#include <libtorrent/create_torrent.hpp>

#include <silkworm/common/directories.hpp>

namespace silkworm {

class BitTorrentClient_ForTest : public BitTorrentClient {
  public:
    using BitTorrentClient::BitTorrentClient;
    using BitTorrentClient::handle_alert;
    using BitTorrentClient::process_alerts;
    using BitTorrentClient::request_save_resume_data;
    using BitTorrentClient::request_torrent_updates;
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
        const TemporaryDirectory tmp_dir;
        std::filesystem::path tmp_magnet_path{tmp_dir.path() / "magnet_links"};
        std::ofstream tmp_magnet_stream{tmp_magnet_path};
        // The following magnet link has malformed URL format ("unsupported URL protocol")
        tmp_magnet_stream << "magnet::?xt=urn:btih:df09957d8a28af3bc5137478885a8003677ca878";
        tmp_magnet_stream.close();
        BitTorrentSettings settings{};
        settings.repository_path = tmp_dir.path();
        settings.magnets_file_path = tmp_magnet_path;
        CHECK_THROWS_AS(BitTorrentClient{settings}, std::runtime_error);
    }
}

TEST_CASE("BitTorrentClient::process_alerts", "[silkworm][snapshot][bittorrent]") {
    SECTION("one invalid magnet link") {
        const TemporaryDirectory tmp_dir;
        std::filesystem::path tmp_magnet_path{tmp_dir.path() / "magnet_links"};
        std::ofstream tmp_magnet_stream{tmp_magnet_path};
        tmp_magnet_stream << "magnet:?xt=urn:btih:df09957d8a28af3bc5137478885a8003677ca878";
        tmp_magnet_stream.close();
        BitTorrentSettings settings{};
        settings.repository_path = tmp_dir.path();
        settings.magnets_file_path = tmp_magnet_path;
        BitTorrentClient_ForTest client{settings};
        CHECK_NOTHROW(client.process_alerts());
    }
}

TEST_CASE("BitTorrentClient::execute_loop", "[silkworm][snapshot][bittorrent]") {
    SECTION("default settings") {
        BitTorrentClient client{BitTorrentSettings{}};
        CHECK_NOTHROW(client.execute_loop());
    }

    SECTION("no magnet links") {
        TemporaryDirectory tmp_dir;
        std::filesystem::path tmp_magnet_path{tmp_dir.path() / "magnet_links"};
        BitTorrentSettings settings{};
        settings.repository_path = tmp_dir.path();
        settings.magnets_file_path = tmp_magnet_path;
        BitTorrentClient client{settings};
        std::thread{[&client]() { client.execute_loop(); }}.join();
    }
}

TEST_CASE("BitTorrentClient::stop", "[silkworm][snapshot][bittorrent]") {
    SECTION("before starting") {
        BitTorrentClient client{BitTorrentSettings{}};
        CHECK_NOTHROW(client.stop());
    }

    SECTION("after empty execution loop") {
        BitTorrentClient client{BitTorrentSettings{}};
        client.execute_loop();
        CHECK_NOTHROW(client.stop());
    }

    SECTION("after empty execution loop on separate thread") {
        BitTorrentClient client{BitTorrentSettings{}};
        std::thread execution_thread{[&client]() { client.execute_loop(); }};
        CHECK_NOTHROW(client.stop());
        execution_thread.join();
    }

    SECTION("interrupt seeding execution loop on separate thread") {
        BitTorrentSettings settings{};
        settings.seeding = true;
        BitTorrentClient client{settings};
        std::thread execution_thread{[&client]() { client.execute_loop(); }};
        CHECK_NOTHROW(client.stop());
        execution_thread.join();
    }

    /*SECTION("after execution loop on separate thread") {
        BitTorrentClient client{BitTorrentSettings{}};
        std::thread execution_thread{[&client]() { client.execute_loop(); }};
        CHECK_NOTHROW(client.stop());
        execution_thread.join();
    }*/

    /*SECTION("stop client after resume by external thread") {
        using std::chrono_literals::operator""ms;
        client.resume();
        std::this_thread::sleep_for(30ms);
        std::thread stop_thread{[&]() { client.stop(); }};
        CHECK_NOTHROW(client.wait_for_completion());
        stop_thread.join();
    }

    SECTION("stop client not yet resumed") {
        CHECK_NOTHROW(client.stop());
        CHECK_NOTHROW(client.wait_for_completion());
    }*/
}

}  // namespace silkworm
