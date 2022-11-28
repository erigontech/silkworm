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

#include <chrono>
#include <fstream>
#include <stdexcept>
#include <string>

#include <CLI/CLI.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/process/environment.hpp>
#include <magic_enum.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/common/log.hpp>
#include <silkworm/snapshot/bittorrent.hpp>
#include <silkworm/snapshot/repository.hpp>
#include <silkworm/snapshot/snapshot.hpp>

#include "common.hpp"

using namespace silkworm;

constexpr const char* kDefaultSnapshotFile{"v1-000000-000500-bodies.seg"};
constexpr int kDefaultPageSize{1024 * 4};
constexpr int kDefaultRepetitions{1};

//! The settings for handling Thorax snapshots
struct SnapSettings {
    std::string snapshot_file_name{kDefaultSnapshotFile};
    int page_size{kDefaultPageSize};
};

//! The settings for handling BitTorrent protocol
struct DownloadSettings : public BitTorrentSettings {
    std::string magnet_uri;
};

//! The Snapshots tools
enum class SnapshotTool {
    count_bodies,
    count_headers,
    create_index,
    decode_segment,
    download
};

//! The overall settings for the snapshot toolbox
struct SnapshotToolboxSettings {
    log::Settings log_settings;
    SnapSettings snapshot_settings;
    DownloadSettings download_settings;
    SnapshotTool tool{SnapshotTool::download};
    int repetitions{kDefaultRepetitions};
};

//! Parse the command-line arguments into the snapshot toolbox settings
void parse_command_line(int argc, char* argv[], CLI::App& app, SnapshotToolboxSettings& settings) {
    auto& log_settings = settings.log_settings;
    auto& snapshot_settings = settings.snapshot_settings;
    auto& bittorrent_settings = settings.download_settings;

    cmd::add_logging_options(app, log_settings);

    std::map<std::string, SnapshotTool> snapshot_tool_mapping{
        {"count_bodies", SnapshotTool::count_bodies},
        {"count_headers", SnapshotTool::count_headers},
        {"decode_segment", SnapshotTool::decode_segment},
        {"download", SnapshotTool::download},
    };
    app.add_option("--tool", settings.tool, "The snapshot tool to use")
        ->capture_default_str()
        ->check(CLI::Range(SnapshotTool::count_bodies, SnapshotTool::download))
        ->transform(CLI::Transformer(snapshot_tool_mapping, CLI::ignore_case))
        ->default_val(SnapshotTool::download);
    app.add_option("--repetitions", settings.repetitions, "The test repetitions")
        ->capture_default_str()
        ->check(CLI::Range(1, 100));
    app.add_option("--file", snapshot_settings.snapshot_file_name, "The path to snapshot file")
        ->capture_default_str();
    app.add_option("--page", snapshot_settings.page_size, "The page size in kB")
        ->capture_default_str()
        ->check(CLI::Range(1, 1024));
    app.add_option("--torrent_dir", bittorrent_settings.repository_path, "The path to torrent file repository")
        ->capture_default_str();
    app.add_option("--magnet", bittorrent_settings.magnet_uri, "The magnet link to download")
        ->capture_default_str();
    app.add_option("--magnet_file", bittorrent_settings.magnets_file_path, "The file containing magnet links to download")
        ->capture_default_str();
    app.add_option("--download_rate_limit", bittorrent_settings.download_rate_limit, "The download rate limit in bytes per second")
        ->capture_default_str()
        ->check(CLI::Range(4 * 1024 * 1024, 128 * 1024 * 1024));
    app.add_option("--upload_rate_limit", bittorrent_settings.upload_rate_limit, "The upload rate limit in bytes per second")
        ->capture_default_str()
        ->check(CLI::Range(1 * 1024 * 1024, 32 * 1024 * 1024));
    app.add_option("--active_downloads", bittorrent_settings.active_downloads, "The max number of downloads active simultaneously")
        ->capture_default_str()
        ->check(CLI::Range(3, 20));

    app.parse(argc, argv);
}

void decode_segment(const SnapSettings& settings, int repetitions) {
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    const auto snap_file{SnapshotFile::parse(std::filesystem::path{settings.snapshot_file_name})};
    if (snap_file) {
        for (int i{0}; i < repetitions; ++i) {
            HeaderSnapshot header_segment{snap_file->path(), snap_file->block_from(), snap_file->block_to()};
            header_segment.reopen_segment();
        }
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    const auto open_duration_micro = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    SILK_INFO << "Open snapshot elapsed: " << open_duration_micro << " msec";
}

void count_bodies(int repetitions) {
    SnapshotRepository snapshot_repo{SnapshotSettings{"../erigon-snapshot/main", false, false}};
    snapshot_repo.reopen_folder();
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    int num_bodies{0};
    uint64_t num_txns{0};
    for (int i{0}; i < repetitions; ++i) {
        snapshot_repo.for_each_body([&](BlockNum number, const db::detail::BlockBodyForStorage* b) -> bool {
            SILK_DEBUG << "Body number: " << number << " txn_count: " << b->txn_count << " #ommers: " << b->ommers.size();
            num_bodies++;
            num_txns += b->txn_count;
            return true;
        });
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    const auto duration_micro = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    SILK_INFO << "How many bodies: " << num_bodies << " txs: " << num_txns << " duration: " << duration_micro << " msec";
}

void count_headers(int repetitions) {
    SnapshotRepository snapshot_repo{{"../erigon-snapshot/main",
                                      false,
                                      false}};
    snapshot_repo.reopen_folder();
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    int count{0};
    for (int i{0}; i < repetitions; ++i) {
        snapshot_repo.for_each_header([&count](const BlockHeader* h) -> bool {
            SILK_DEBUG << "Header number: " << h->number << " hash: " << to_hex(h->hash());
            ++count;
            return true;
        });
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    const auto duration_micro = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    SILK_INFO << "How many headers: " << count << " duration: " << duration_micro << " msec";
}

void create_index(const SnapSettings& settings, int repetitions) {
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    const auto snap_file{SnapshotFile::parse(std::filesystem::path{settings.snapshot_file_name})};
    if (snap_file) {
        for (int i{0}; i < repetitions; ++i) {
            HeaderSnapshot header_segment{snap_file->path(), snap_file->block_from(), snap_file->block_to()};
            header_segment.reopen_index();
        }
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    const auto open_duration_micro = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    SILK_INFO << "Create index elapsed: " << open_duration_micro << " msec";
}

void download(const BitTorrentSettings& settings, int /*repetitions*/) {
    try {
        BitTorrentSettings bit_torrent_settings;
        bit_torrent_settings.magnets_file_path = settings.magnets_file_path;
        BitTorrentClient client{bit_torrent_settings};

        boost::asio::io_context scheduler;
        boost::asio::signal_set signals{scheduler, SIGINT, SIGTERM};
        signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
            std::cout << "\n";
            SILK_INFO << "Signal caught, error: " << error << " number: " << signal_number;
            client.stop();
            SILK_DEBUG << "Torrent client stopped";
            scheduler.stop();
            SILK_DEBUG << "Scheduler stopped";
        });
        std::thread scheduler_thread{[&scheduler]() { scheduler.run(); }};
        SILK_DEBUG << "Signals registered on scheduler " << &scheduler;

        SILK_INFO << "Bittorrent async download started for magnet file: " << settings.magnets_file_path;
        client.execute_loop();
        SILK_INFO << "Bittorrent async download completed for magnet file: " << settings.magnets_file_path;

        scheduler_thread.join();
    } catch (...) {
        std::exception_ptr ex = std::current_exception();
        if (ex) std::rethrow_exception(ex);
    }
}

int main(int argc, char* argv[]) {
    CLI::App app{"Snapshots toolbox"};

    try {
        SnapshotToolboxSettings settings;
        parse_command_line(argc, argv, app, settings);

        const auto pid = boost::this_process::get_id();
        SILK_LOG << "Snapshots toolbox starting [pid=" << std::to_string(pid) << "]";

        const auto node_name{cmd::get_node_name_from_build_info(silkworm_get_buildinfo())};
        SILK_LOG << "Snapshots toolbox build info: " << node_name;

        auto& log_settings = settings.log_settings;

        // Initialize logging with custom settings
        log::init(log_settings);

        if (settings.tool == SnapshotTool::count_bodies) {
            count_bodies(settings.repetitions);
        } else if (settings.tool == SnapshotTool::count_headers) {
            count_headers(settings.repetitions);
        } else if (settings.tool == SnapshotTool::create_index) {
            create_index(settings.snapshot_settings, settings.repetitions);
        } else if (settings.tool == SnapshotTool::decode_segment) {
            decode_segment(settings.snapshot_settings, settings.repetitions);
        } else if (settings.tool == SnapshotTool::download) {
            download(settings.download_settings, settings.repetitions);
        } else {
            throw std::invalid_argument{"unknown tool: " + std::string{magic_enum::enum_name<>(settings.tool)}};
        }

        SILK_LOG << "Snapshots toolbox exiting [pid=" << std::to_string(pid) << "]";
        return 0;
    } catch (const CLI::ParseError& pe) {
        return app.exit(pe);
    } catch (const std::exception& e) {
        SILK_CRIT << "Snapshots toolbox exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        SILK_CRIT << "Snapshots toolbox exiting due to unexpected exception";
        return -3;
    }
}
