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
#include <boost/process/environment.hpp>
#include <magic_enum.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/core/chain/config.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/bittorrent/client.hpp>
#include <silkworm/node/snapshot/index.hpp>
#include <silkworm/node/snapshot/repository.hpp>
#include <silkworm/node/snapshot/snapshot.hpp>
#include <silkworm/node/snapshot/sync.hpp>

#include "../common/common.hpp"
#include "../common/shutdown_signal.hpp"

using namespace silkworm;
using namespace silkworm::cmd::common;
using namespace silkworm::snapshot;

const std::vector<std::string> kDefaultSnapshotFiles{
    "v1-000000-000500-bodies.seg",
    "v1-000000-000500-headers.seg",
    "v1-000000-000500-transactions.seg",
};
constexpr int kDefaultPageSize{4 * 1024};  // 4kB
constexpr int kDefaultRepetitions{1};

//! The settings for handling Thorax snapshots customized for this tool
struct SnapSettings : public SnapshotSettings {
    std::vector<std::string> snapshot_file_names{kDefaultSnapshotFiles};
    int page_size{kDefaultPageSize};
    bool skip_system_txs{true};
    std::string lookup_hash;
};

//! The settings for handling BitTorrent protocol customized for this tool
struct DownloadSettings : public BitTorrentSettings {
    std::string magnet_uri;
};

//! The Snapshots tools
enum class SnapshotTool {
    count_bodies,
    count_headers,
    create_index,
    decode_segment,
    download,
    lookup_header,
    sync
};

//! The overall settings for the snapshot toolbox
struct SnapshotToolboxSettings {
    log::Settings log_settings;
    SnapSettings snapshot_settings;
    DownloadSettings download_settings;
    SnapshotTool tool{SnapshotTool::download};
    int repetitions{kDefaultRepetitions};
};

struct HashValidator : public CLI::Validator {
    explicit HashValidator() {
        func_ = [&](const std::string& value) -> std::string {
            const auto hash{Hash::from_hex(value)};
            if (!hash) return "Value " + value + " is not a valid 32-byte hash";
            return {};
        };
    }
};

//! Parse the command-line arguments into the snapshot toolbox settings
void parse_command_line(int argc, char* argv[], CLI::App& app, SnapshotToolboxSettings& settings) {
    auto& log_settings = settings.log_settings;
    auto& snapshot_settings = settings.snapshot_settings;
    auto& bittorrent_settings = settings.download_settings;

    bittorrent_settings.repository_path = snapshot_settings.repository_dir / ".torrent";
    bittorrent_settings.magnets_file_path = ".magnet_links";

    add_logging_options(app, log_settings);

    std::map<std::string, SnapshotTool> snapshot_tool_mapping{
        {"count_bodies", SnapshotTool::count_bodies},
        {"count_headers", SnapshotTool::count_headers},
        {"create_index", SnapshotTool::create_index},
        {"decode_segment", SnapshotTool::decode_segment},
        {"download", SnapshotTool::download},
        {"lookup_header", SnapshotTool::lookup_header},
        {"sync", SnapshotTool::sync},
    };
    app.add_option("--tool", settings.tool, "The snapshot tool to use")
        ->capture_default_str()
        ->check(CLI::Range(SnapshotTool::count_bodies, SnapshotTool::sync))
        ->transform(CLI::Transformer(snapshot_tool_mapping, CLI::ignore_case))
        ->default_val(SnapshotTool::download);
    app.add_option("--repetitions", settings.repetitions, "The test repetitions")
        ->capture_default_str()
        ->check(CLI::Range(1, 100));
    app.add_option("--files", snapshot_settings.snapshot_file_names, "The path to snapshot files")
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
    app.add_flag("--seeding", bittorrent_settings.seeding, "Flag indicating if torrents should be seeded when download is finished")
        ->capture_default_str();
    app.add_option("--hash", snapshot_settings.lookup_hash, "The hash to lookup in snapshot files")
        ->capture_default_str()
        ->check(HashValidator{});

    app.parse(argc, argv);
}

//! Convert one duration into another one returning the number of ticks for the latter one
template <typename D, typename R, typename P>
auto duration_as(const std::chrono::duration<R, P>& elapsed) {
    return std::chrono::duration_cast<D>(elapsed).count();
}

void decode_segment(const SnapSettings& settings, int repetitions) {
    for (const auto& snapshot_file_name : settings.snapshot_file_names) {
        SILK_INFO << "Decode snapshot: " << snapshot_file_name;
        std::chrono::time_point start{std::chrono::steady_clock::now()};
        const auto snap_file{SnapshotPath::parse(std::filesystem::path{snapshot_file_name})};
        if (snap_file) {
            for (int i{0}; i < repetitions; ++i) {
                HeaderSnapshot header_segment{snap_file->path(), snap_file->block_from(), snap_file->block_to()};
                header_segment.reopen_segment();
            }
        }
        std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
        SILK_INFO << "Decode snapshot elapsed: " << duration_as<std::chrono::milliseconds>(elapsed) << " msec";
    }
}

void count_bodies(const SnapSettings& settings, int repetitions) {
    SnapshotRepository snapshot_repo{settings};
    snapshot_repo.reopen_folder();
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    int num_bodies{0};
    uint64_t num_txns{0};
    for (int i{0}; i < repetitions; ++i) {
        snapshot_repo.for_each_body([&](BlockNum number, const db::detail::BlockBodyForStorage* b) -> bool {
            // If *system transactions* should not be counted, skip first and last tx in block body
            const auto base_txn_id{settings.skip_system_txs ? b->base_txn_id + 1 : b->base_txn_id};
            const auto txn_count{settings.skip_system_txs and b->txn_count >= 2 ? b->txn_count - 2 : b->txn_count};
            SILK_DEBUG << "Body number: " << number << " base_txn_id: " << base_txn_id << " txn_count: " << txn_count
                       << " #ommers: " << b->ommers.size();
            num_bodies++;
            num_txns += txn_count;
            return true;
        });
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    const auto duration = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    SILK_INFO << "How many bodies: " << num_bodies << " txs: " << num_txns << " duration: " << duration << " msec";
}

void count_headers(const SnapSettings& settings, int repetitions) {
    SnapshotRepository snapshot_repo{settings};
    snapshot_repo.reopen_folder();
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    int count{0};
    for (int i{0}; i < repetitions; ++i) {
        snapshot_repo.for_each_header([&count](const BlockHeader* h) -> bool {
            ++count;
            if (h->number % 500'000 == 0) {
                SILK_INFO << "Header number: " << h->number << " hash: " << to_hex(h->hash());
            }
            return true;
        });
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "How many headers: " << count << " duration: " << duration_as<std::chrono::milliseconds>(elapsed) << " msec";
}

void create_index(const SnapSettings& settings, int repetitions) {
    for (const auto& snapshot_file_name : settings.snapshot_file_names) {
        SILK_INFO << "Create index for snapshot: " << snapshot_file_name;
        std::chrono::time_point start{std::chrono::steady_clock::now()};
        const auto snap_file{SnapshotPath::parse(std::filesystem::path{snapshot_file_name})};
        if (snap_file) {
            for (int i{0}; i < repetitions; ++i) {
                switch (snap_file->type()) {
                    case SnapshotType::headers: {
                        HeaderIndex index{*snap_file};
                        index.build();
                        break;
                    }
                    case SnapshotType::bodies: {
                        BodyIndex index{*snap_file};
                        index.build();
                        break;
                    }
                    case SnapshotType::transactions: {
                        TransactionIndex index{*snap_file};
                        index.build();
                        break;
                    }
                    default: {
                        SILKWORM_ASSERT(false);
                    }
                }
            }
        } else {
            SILK_ERROR << "Invalid snapshot file: " << snapshot_file_name;
        }
        std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
        SILK_INFO << "Create index elapsed: " << duration_as<std::chrono::milliseconds>(elapsed) << " msec";
    }
}

void download(const BitTorrentSettings& settings) {
    std::chrono::time_point start{std::chrono::steady_clock::now()};

    BitTorrentClient client{settings};

    boost::asio::io_context scheduler;
    ShutdownSignal shutdown_signal{scheduler};
    shutdown_signal.on_signal([&](ShutdownSignal::SignalNumber /*num*/) {
        client.stop();
        SILK_DEBUG << "Torrent client stopped";
        scheduler.stop();
        SILK_DEBUG << "Scheduler stopped";
    });
    std::thread scheduler_thread{[&scheduler]() { scheduler.run(); }};

    SILK_INFO << "Bittorrent async download started for magnet file: " << *settings.magnets_file_path;
    client.execute_loop();
    SILK_INFO << "Bittorrent async download completed for magnet file: " << *settings.magnets_file_path;

    scheduler_thread.join();

    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Download elapsed: " << duration_as<std::chrono::seconds>(elapsed) << " sec";
}

void lookup_header(const SnapSettings& settings) {
    const auto hash{Hash::from_hex(settings.lookup_hash)};
    SILK_INFO << "Lookup header hash: " << hash->to_hex();
    std::chrono::time_point start{std::chrono::steady_clock::now()};

    const HeaderSnapshot* matching_snapshot{nullptr};
    SnapshotRepository snapshot_repository{settings};
    snapshot_repository.reopen_folder();
    snapshot_repository.view_header_segments([&](const HeaderSnapshot* snapshot) -> bool {
        const auto header{snapshot->header_by_hash(*hash)};
        if (header) {
            matching_snapshot = snapshot;
        }
        return header.has_value();
    });
    if (matching_snapshot) {
        SILK_INFO << "Lookup header hash: " << hash->to_hex() << " found in: " << matching_snapshot->path().filename();
    } else {
        SILK_INFO << "Lookup header hash: " << hash->to_hex() << " NOT found";
    }

    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup header elapsed: " << duration_as<std::chrono::milliseconds>(elapsed) << " msec";
}

void sync(const SnapSettings& snapshot_settings) {
    std::chrono::time_point start{std::chrono::steady_clock::now()};

    SnapshotRepository snapshot_repository{snapshot_settings};
    SnapshotSync snapshot_sync{&snapshot_repository, kMainnetConfig};
    snapshot_sync.download_snapshots(snapshot_settings.snapshot_file_names);

    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Sync elapsed: " << duration_as<std::chrono::seconds>(elapsed) << " sec";
}

int main(int argc, char* argv[]) {
    CLI::App app{"Snapshots toolbox"};

    try {
        SnapshotToolboxSettings settings;
        parse_command_line(argc, argv, app, settings);

        const auto pid = boost::this_process::get_id();
        SILK_LOG << "Snapshots toolbox starting [pid=" << std::to_string(pid) << "]";

        const auto node_name{get_node_name_from_build_info(silkworm_get_buildinfo())};
        SILK_LOG << "Snapshots toolbox build info: " << node_name;

        auto& log_settings = settings.log_settings;

        // Initialize logging with custom settings
        log::init(log_settings);

        if (settings.tool == SnapshotTool::count_bodies) {
            count_bodies(settings.snapshot_settings, settings.repetitions);
        } else if (settings.tool == SnapshotTool::count_headers) {
            count_headers(settings.snapshot_settings, settings.repetitions);
        } else if (settings.tool == SnapshotTool::create_index) {
            create_index(settings.snapshot_settings, settings.repetitions);
        } else if (settings.tool == SnapshotTool::decode_segment) {
            decode_segment(settings.snapshot_settings, settings.repetitions);
        } else if (settings.tool == SnapshotTool::download) {
            download(settings.download_settings);
        } else if (settings.tool == SnapshotTool::lookup_header) {
            lookup_header(settings.snapshot_settings);
        } else if (settings.tool == SnapshotTool::sync) {
            sync(settings.snapshot_settings);
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
