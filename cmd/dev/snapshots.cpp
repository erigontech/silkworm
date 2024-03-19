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
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>

#include <CLI/CLI.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/process/environment.hpp>
#include <intx/intx.hpp>
#include <magic_enum.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/snapshot_sync.hpp>
#include <silkworm/db/snapshots/bittorrent/client.hpp>
#include <silkworm/db/snapshots/index.hpp>
#include <silkworm/db/snapshots/repository.hpp>
#include <silkworm/db/snapshots/seg/seg_zip.hpp>
#include <silkworm/db/snapshots/snapshot.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>

#include "../common/common.hpp"
#include "../common/shutdown_signal.hpp"

using namespace silkworm;
using namespace silkworm::cmd::common;
using namespace silkworm::snapshots;

constexpr int kDefaultPageSize{4 * 1024};  // 4kB
constexpr int kDefaultRepetitions{1};

//! The settings for handling Thorax snapshots customized for this tool
struct SnapSettings : public SnapshotSettings {
    std::filesystem::path input_file_path;
    std::optional<std::string> snapshot_file_name;
    int page_size{kDefaultPageSize};
    bool skip_system_txs{true};
    std::optional<std::string> lookup_hash;
    std::optional<BlockNum> lookup_number;
    bool print{true};
};

//! The settings for handling BitTorrent protocol customized for this tool
struct DownloadSettings : public bittorrent::BitTorrentSettings {
    std::string magnet_uri;
};

static const auto kTorrentRepoPath{bittorrent::BitTorrentSettings::kDefaultTorrentRepoPath};

//! The available subcommands in snapshots utility
//! \warning reducing the enum base type size as suggested by clang-tidy breaks CLI11
enum class SnapshotTool {  // NOLINT(performance-enum-size)
    count_bodies,
    count_headers,
    create_index,
    open_index,
    decode_segment,
    download,
    lookup_header,
    lookup_body,
    lookup_txn,
    seg_zip,
    seg_unzip,
    sync
};

//! The overall settings for the snapshot toolbox
struct SnapshotToolboxSettings {
    log::Settings log_settings;
    SnapSettings snapshot_settings;
    DownloadSettings download_settings;
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

struct BlockNumberValidator : public CLI::Validator {
    explicit BlockNumberValidator() {
        func_ = [&](const std::string& value) -> std::string {
            try {
                std::stoul(value);
            } catch (const std::exception& ex) {
                return "Value " + value + " is not a valid block number: " + ex.what();
            }
            return {};
        };
    }
};

//! Parse the command-line arguments into the snapshot toolbox settings
void parse_command_line(int argc, char* argv[], CLI::App& app, SnapshotToolboxSettings& settings) {
    auto& log_settings = settings.log_settings;
    auto& snapshot_settings = settings.snapshot_settings;
    auto& bittorrent_settings = settings.download_settings;

    bittorrent_settings.repository_path = snapshot_settings.repository_dir / kTorrentRepoPath;
    bittorrent_settings.magnets_file_path = ".magnet_links";

    add_logging_options(app, log_settings);

    std::map<SnapshotTool, CLI::App*> commands;
    for (auto& [tool, name] : magic_enum::enum_entries<SnapshotTool>()) {
        commands[tool] = app.add_subcommand(std::string{name});
    }
    app.require_subcommand(1);

    app.add_option("--snapshot_dir", snapshot_settings.repository_dir, "Path to snapshot repository")
        ->capture_default_str();
    app.add_option("--repetitions", settings.repetitions, "How many times to repeat the execution")
        ->capture_default_str()
        ->check(CLI::Range(1, 100));
    app.add_option("--page", snapshot_settings.page_size, "Page size in kB")
        ->capture_default_str()
        ->check(CLI::Range(1, 1024));
    app.add_flag("--print", snapshot_settings.print, "Flag indicating if console dump is enabled or not")
        ->capture_default_str();

    for (auto& cmd : {commands[SnapshotTool::lookup_header],
                      commands[SnapshotTool::lookup_body],
                      commands[SnapshotTool::lookup_txn],
                      commands[SnapshotTool::open_index]}) {
        cmd->add_option("--number", snapshot_settings.lookup_number, "Block number to lookup in snapshot files")
            ->capture_default_str()
            ->check(BlockNumberValidator{});
    }
    for (auto& cmd : {commands[SnapshotTool::lookup_header],
                      commands[SnapshotTool::lookup_body],
                      commands[SnapshotTool::lookup_txn]}) {
        cmd->add_option("--hash", snapshot_settings.lookup_hash, "Hash to lookup in snapshot files")
            ->capture_default_str()
            ->check(HashValidator{});
    }
    for (auto& cmd : {commands[SnapshotTool::download]}) {
        cmd->add_option("--torrent_dir", bittorrent_settings.repository_path, "Path to torrent file repository")
            ->capture_default_str();
        cmd->add_option("--magnet", bittorrent_settings.magnet_uri, "Magnet link to download")
            ->capture_default_str();
        cmd->add_option("--magnet_file", bittorrent_settings.magnets_file_path, "File containing magnet links to download")
            ->capture_default_str();
        cmd->add_option("--download_rate_limit", bittorrent_settings.download_rate_limit, "Download rate limit in bytes per second")
            ->capture_default_str()
            ->check(CLI::Range(4 * 1024 * 1024, 128 * 1024 * 1024));
        cmd->add_option("--upload_rate_limit", bittorrent_settings.upload_rate_limit, "Upload rate limit in bytes per second")
            ->capture_default_str()
            ->check(CLI::Range(1 * 1024 * 1024, 32 * 1024 * 1024));
        cmd->add_option("--active_downloads", bittorrent_settings.active_downloads, "Max number of downloads active simultaneously")
            ->capture_default_str()
            ->check(CLI::Range(3, 20));
        cmd->add_flag("--seeding", bittorrent_settings.seeding, "Flag indicating if torrents should be seeded when download is finished")
            ->capture_default_str();
    }
    for (auto& cmd : {commands[SnapshotTool::create_index],
                      commands[SnapshotTool::open_index],
                      commands[SnapshotTool::decode_segment]}) {
        cmd->add_option("snapshot_file", snapshot_settings.snapshot_file_name, "Path to snapshot file")
            ->required()
            ->capture_default_str();
    }
    commands[SnapshotTool::seg_zip]
        ->add_option("file", snapshot_settings.input_file_path, "Raw words file to compress")
        ->required()
        ->check(CLI::ExistingFile);
    commands[SnapshotTool::seg_unzip]
        ->add_option("file", snapshot_settings.input_file_path, ".seg file to decompress")
        ->required()
        ->check(CLI::ExistingFile);

    app.parse(argc, argv);

    bittorrent_settings.repository_path = snapshot_settings.repository_dir / kTorrentRepoPath;
}

//! Convert one duration into another one returning the number of ticks for the latter one
template <typename D, typename R, typename P>
auto duration_as(const std::chrono::duration<R, P>& elapsed) {
    return std::chrono::duration_cast<D>(elapsed).count();
}

void decode_segment(const SnapSettings& settings, int repetitions) {
    ensure(settings.snapshot_file_name.has_value(), "decode_segment: --snapshot_file must be specified");
    SILK_INFO << "Decode snapshot: " << *settings.snapshot_file_name;
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    const auto snap_file{SnapshotPath::parse(std::filesystem::path{*settings.snapshot_file_name})};
    if (snap_file) {
        std::unique_ptr<Snapshot> snapshot;
        for (int i{0}; i < repetitions; ++i) {
            switch (snap_file->type()) {
                case SnapshotType::headers: {
                    snapshot = std::make_unique<HeaderSnapshot>(*snap_file);
                } break;
                case SnapshotType::bodies: {
                    snapshot = std::make_unique<BodySnapshot>(*snap_file);
                } break;
                default: {
                    snapshot = std::make_unique<TransactionSnapshot>(*snap_file);
                }
            }
            snapshot->reopen_segment();
        }
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Decode snapshot elapsed: " << duration_as<std::chrono::milliseconds>(elapsed) << " msec";
}

void count_bodies(const SnapSettings& settings, int repetitions) {
    SnapshotRepository snapshot_repo{settings};
    snapshot_repo.reopen_folder();
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    int num_bodies{0};
    uint64_t num_txns{0};
    for (int i{0}; i < repetitions; ++i) {
        const bool success = snapshot_repo.for_each_body([&](BlockNum number, const BlockBodyForStorage* b) -> bool {
            // If *system transactions* should not be counted, skip first and last tx in block body
            const auto base_txn_id{settings.skip_system_txs ? b->base_txn_id + 1 : b->base_txn_id};
            const auto txn_count{settings.skip_system_txs && b->txn_count >= 2 ? b->txn_count - 2 : b->txn_count};
            SILK_DEBUG << "Body number: " << number << " base_txn_id: " << base_txn_id << " txn_count: " << txn_count
                       << " #ommers: " << b->ommers.size();
            num_bodies++;
            num_txns += txn_count;
            return true;
        });
        ensure(success, "count_bodies: for_each_body failed");
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
        const bool success = snapshot_repo.for_each_header([&count](const BlockHeader* h) -> bool {
            ++count;
            if (h->number % 50'000 == 0) {
                SILK_INFO << "Header number: " << h->number << " hash: " << to_hex(h->hash());
            }
            return true;
        });
        ensure(success, "count_headers: for_each_header failed");
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "How many headers: " << count << " duration: " << duration_as<std::chrono::milliseconds>(elapsed) << " msec";
}

void create_index(const SnapSettings& settings, int repetitions) {
    ensure(settings.snapshot_file_name.has_value(), "create_index: --snapshot_file must be specified");
    SILK_INFO << "Create index for snapshot: " << *settings.snapshot_file_name;
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    const auto snap_file{SnapshotPath::parse(std::filesystem::path{*settings.snapshot_file_name})};
    if (snap_file) {
        for (int i{0}; i < repetitions; ++i) {
            switch (snap_file->type()) {
                case SnapshotType::headers: {
                    auto index = HeaderIndex::make(*snap_file);
                    index.build();
                    break;
                }
                case SnapshotType::bodies: {
                    auto index = BodyIndex::make(*snap_file);
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
        SILK_ERROR << "Invalid snapshot file: " << *settings.snapshot_file_name;
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Create index elapsed: " << duration_as<std::chrono::milliseconds>(elapsed) << " msec";
}

void open_index(const SnapSettings& settings) {
    ensure(settings.snapshot_file_name.has_value(), "open_index: --snapshot_file must be specified");
    std::filesystem::path segment_file_path{settings.repository_dir / *settings.snapshot_file_name};
    SILK_INFO << "Open index for snapshot: " << segment_file_path;
    const auto snapshot_path{snapshots::SnapshotPath::parse(segment_file_path)};
    ensure(snapshot_path.has_value(), [&]() { return "open_index: invalid snapshot file " + segment_file_path.filename().string(); });
    const auto index_path{snapshot_path->index_file()};
    SILK_INFO << "Index file: " << index_path.path();
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    rec_split::RecSplitIndex idx{index_path.path()};
    SILK_INFO << "Index properties: empty=" << idx.empty() << " base_data_id=" << idx.base_data_id()
              << " double_enum_index=" << idx.double_enum_index() << " less_false_positives=" << idx.less_false_positives();
    if (idx.double_enum_index()) {
        if (settings.lookup_number) {
            const uint64_t data_id{*settings.lookup_number};
            const uint64_t enumeration{data_id - idx.base_data_id()};
            if (enumeration < idx.key_count()) {
                SILK_INFO << "Offset by ordinal lookup for " << data_id << ": " << idx.ordinal_lookup(enumeration);
            } else {
                SILK_WARN << "Invalid absolute data number " << data_id << " for ordinal lookup";
            }
        } else {
            for (size_t i{0}; i < idx.key_count(); ++i) {
                if (i % (idx.key_count() / 10) == 0) {
                    SILK_INFO << "Offset by ordinal lookup for " << i << ": " << idx.ordinal_lookup(i)
                              << " [existence filter: " << int(idx.existence_filter()[i]) << "]";
                }
            }
        }
    } else {
        SILK_INFO << "Index does not support 2-layer enum indexing";
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Open index elapsed: " << duration_as<std::chrono::milliseconds>(elapsed) << " msec";
}

void download(const bittorrent::BitTorrentSettings& settings) {
    std::chrono::time_point start{std::chrono::steady_clock::now()};

    bittorrent::BitTorrentClient client{settings};
    SILK_INFO << "Bittorrent download started in repo: " << settings.repository_path.string();

    boost::asio::io_context scheduler;
    ShutdownSignal shutdown_signal{scheduler.get_executor()};
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

static void print_header(const BlockHeader& header, const std::string& snapshot_filename) {
    std::cout << "Header found in: " << snapshot_filename << "\n"
              << "hash=" << to_hex(header.hash()) << "\n"
              << "parent_hash=" << to_hex(header.parent_hash) << "\n"
              << "number=" << header.number << "\n"
              << "beneficiary=" << header.beneficiary << "\n"
              << "ommers_hash=" << to_hex(header.ommers_hash) << "\n"
              << "state_root=" << to_hex(header.state_root) << "\n"
              << "transactions_root=" << to_hex(header.transactions_root) << "\n"
              << "receipts_root=" << to_hex(header.receipts_root) << "\n"
              << "withdrawals_root=" << (header.withdrawals_root ? to_hex(*header.withdrawals_root) : "") << "\n"
              << "beneficiary=" << header.beneficiary << "\n"
              << "timestamp=" << header.timestamp << "\n"
              << "nonce=" << to_hex(header.nonce) << "\n"
              << "prev_randao=" << to_hex(header.prev_randao) << "\n"
              << "base_fee_per_gas=" << (header.base_fee_per_gas ? intx::to_string(*header.base_fee_per_gas) : "") << "\n"
              << "difficulty=" << intx::to_string(header.difficulty) << "\n"
              << "gas_limit=" << header.gas_limit << "\n"
              << "gas_used=" << header.gas_used << "\n"
              << "blob_gas_used=" << header.blob_gas_used.value_or(0) << "\n"
              << "excess_blob_gas=" << header.excess_blob_gas.value_or(0) << "\n"
              << "logs_bloom=" << to_hex(header.logs_bloom) << "\n"
              << "extra_data=" << to_hex(header.extra_data) << "\n"
              << "rlp=" << to_hex([&]() { Bytes b; rlp::encode(b, header); return b; }()) << "\n";
}

void lookup_header_by_hash(const SnapSettings& settings) {
    const auto hash{Hash::from_hex(*settings.lookup_hash)};
    ensure(hash.has_value(), "lookup_header_by_hash: lookup_hash is not a valid hash");
    SILK_INFO << "Lookup header hash: " << hash->to_hex();
    std::chrono::time_point start{std::chrono::steady_clock::now()};

    const HeaderSnapshot* matching_snapshot{nullptr};
    std::optional<BlockHeader> matching_header;
    SnapshotRepository snapshot_repository{settings};
    snapshot_repository.reopen_folder();
    snapshot_repository.view_header_segments([&](const HeaderSnapshot* snapshot) -> bool {
        const auto header{snapshot->header_by_hash(*hash)};
        if (header) {
            matching_header = header;
            matching_snapshot = snapshot;
        }
        return header.has_value();
    });
    if (matching_snapshot) {
        SILK_INFO << "Lookup header hash: " << hash->to_hex() << " found in: " << matching_snapshot->path().filename();
        if (matching_header && settings.print) {
            print_header(*matching_header, matching_snapshot->path().filename());
        }
    } else {
        SILK_WARN << "Lookup header hash: " << hash->to_hex() << " NOT found";
    }

    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup header elapsed: " << duration_as<std::chrono::milliseconds>(elapsed) << " msec";
}

void lookup_header_by_number(const SnapSettings& settings) {
    const auto block_number{*settings.lookup_number};
    SILK_INFO << "Lookup header number: " << block_number;
    std::chrono::time_point start{std::chrono::steady_clock::now()};

    SnapshotRepository snapshot_repository{settings};
    snapshot_repository.reopen_folder();
    const auto header_snapshot{snapshot_repository.find_header_segment(block_number)};
    if (header_snapshot) {
        const auto header{header_snapshot->header_by_number(block_number)};
        ensure(header.has_value(),
               [&]() { return "lookup_header_by_number: " + std::to_string(block_number) + " NOT found in " + header_snapshot->path().filename(); });
        SILK_INFO << "Lookup header number: " << block_number << " found in: " << header_snapshot->path().filename();
        if (settings.print) {
            print_header(*header, header_snapshot->path().filename());
        }
    } else {
        SILK_WARN << "Lookup header number: " << block_number << " NOT found";
    }

    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup header elapsed: " << duration_as<std::chrono::milliseconds>(elapsed) << " msec";
}

void lookup_header(const SnapSettings& settings) {
    ensure(settings.lookup_hash || settings.lookup_number, "lookup_header: either --hash or --number must be used");
    if (settings.lookup_hash) {
        lookup_header_by_hash(settings);
    } else {
        lookup_header_by_number(settings);
    }
}

static void print_body(const StoredBlockBody& body, const std::string& snapshot_filename) {
    std::cout << "Body found in: " << snapshot_filename << "\n"
              << "base_txn_id=" << body.base_txn_id << "\n"
              << "txn_count=" << body.txn_count << "\n"
              << "rlp=" << to_hex(body.encode()) << "\n";
}

void lookup_body_in_one(const SnapSettings& settings, BlockNum block_number, const std::string& file_name) {
    const auto snapshot_path = SnapshotPath::parse(settings.repository_dir / file_name);
    ensure(snapshot_path.has_value(), "lookup_body: --snapshot_file is invalid snapshot file");
    SnapshotRepository snapshot_repository{settings};
    snapshot_repository.reopen_file(*snapshot_path);

    std::chrono::time_point start{std::chrono::steady_clock::now()};
    const auto body_snapshot{snapshot_repository.get_body_segment(*snapshot_path)};
    ensure(body_snapshot, [&]() { return "lookup_body: body segment not found for snapshot file: " + snapshot_path->path().string(); });
    const auto body{body_snapshot->body_by_number(block_number)};
    if (body) {
        SILK_INFO << "Lookup body number: " << block_number << " found in: " << body_snapshot->path().filename();
        if (settings.print) {
            print_body(*body, body_snapshot->path().filename());
        }
    } else {
        SILK_WARN << "Lookup body number: " << block_number << " NOT found in: " << body_snapshot->path().filename();
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup body elapsed: " << duration_as<std::chrono::microseconds>(elapsed) << " usec";
}

void lookup_body_in_all(const SnapSettings& settings, BlockNum block_number) {
    SnapshotRepository snapshot_repository{settings};
    snapshot_repository.reopen_folder();

    std::chrono::time_point start{std::chrono::steady_clock::now()};
    const auto body_snapshot{snapshot_repository.find_body_segment(block_number)};
    if (body_snapshot) {
        const auto body{body_snapshot->body_by_number(block_number)};
        ensure(body.has_value(),
               [&]() { return "lookup_body: " + std::to_string(block_number) + " NOT found in " + body_snapshot->path().filename(); });
        SILK_INFO << "Lookup body number: " << block_number << " found in: " << body_snapshot->path().filename();
        if (settings.print) {
            print_body(*body, body_snapshot->path().filename());
        }
    } else {
        SILK_WARN << "Lookup body number: " << block_number << " NOT found";
    }

    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup header elapsed: " << duration_as<std::chrono::microseconds>(elapsed) << " usec";
}

void lookup_body(const SnapSettings& settings) {
    ensure(settings.lookup_number.has_value(), "lookup_body: --number must be specified");
    const auto block_number{*settings.lookup_number};
    SILK_INFO << "Lookup body number: " << block_number;

    if (settings.snapshot_file_name) {
        lookup_body_in_one(settings, block_number, *settings.snapshot_file_name);
    } else {
        lookup_body_in_all(settings, block_number);
    }
}

static void print_txn(const Transaction& txn, const std::string& snapshot_filename) {
    std::cout << "Transaction found in: " << snapshot_filename << "\n"
              << "hash=" << to_hex(txn.hash()) << "\n"
              << "type=" << magic_enum::enum_name(txn.type) << "\n"
              << "from=" << (txn.sender() ? address_to_hex(*txn.sender()) : "") << "\n"
              << "to=" << (txn.to ? address_to_hex(*txn.to) : "") << "\n"
              << "chain_id=" << (txn.chain_id ? intx::to_string(*txn.chain_id) : "") << "\n"
              << "nonce=" << txn.nonce << "\n"
              << "value=" << intx::to_string(txn.value) << "\n"
              << "gas_limit=" << txn.gas_limit << "\n"
              << "max_fee_per_gas=" << intx::to_string(txn.max_fee_per_gas) << "\n"
              << "max_fee_per_blob_gas=" << intx::to_string(txn.max_fee_per_blob_gas) << "\n"
              << "max_priority_fee_per_gas=" << intx::to_string(txn.max_priority_fee_per_gas) << "\n"
              << "odd_y_parity=" << txn.odd_y_parity << "\n"
              << "v=" << intx::to_string(txn.v()) << "\n"
              << "r=" << intx::to_string(txn.r) << "\n"
              << "s=" << intx::to_string(txn.s) << "\n"
              << "data=" << to_hex(txn.data) << "\n"
              << "access_list=" << ([&]() {
                     std::string rep{"["};
                     for (size_t i{0}; i < txn.access_list.size(); ++i) {
                         const auto& access_entry{txn.access_list[i]};
                         rep.append(address_to_hex(access_entry.account));
                         rep.append(" : [");
                         for (size_t j{0}; j < access_entry.storage_keys.size(); ++j) {
                             rep.append(to_hex(access_entry.storage_keys[j].bytes));
                             if (j != access_entry.storage_keys.size() - 1) rep.append(", ");
                         }
                         if (i != txn.access_list.size() - 1) rep.append("], ");
                     }
                     rep.append("]");
                     return rep;
                 }())
              << "\n"
              << "blob_versioned_hashes=" << ([&]() {
                     std::string rep{"["};
                     for (size_t i{0}; i < txn.blob_versioned_hashes.size(); ++i) {
                         rep.append(to_hex(txn.blob_versioned_hashes[i]));
                         if (i != txn.blob_versioned_hashes.size() - 1) rep.append(", ");
                     }
                     rep.append("]");
                     return rep;
                 }())
              << "\n"
              << "rlp=" << to_hex([&]() { Bytes b; rlp::encode(b, txn); return b; }()) << "\n";
}

void lookup_txn_by_hash_in_one(const SnapSettings& settings, const Hash& hash, const std::string& file_name) {
    const auto snapshot_path = SnapshotPath::parse(settings.repository_dir / file_name);
    ensure(snapshot_path.has_value(), "lookup_tx_by_hash_in_one: --snapshot_file is invalid snapshot file");
    SnapshotRepository snapshot_repository{settings};
    snapshot_repository.reopen_file(*snapshot_path);

    std::chrono::time_point start{std::chrono::steady_clock::now()};
    const auto tx_snapshot{snapshot_repository.get_tx_segment(*snapshot_path)};
    if (tx_snapshot) {
        const auto transaction{tx_snapshot->txn_by_hash(hash)};
        if (transaction) {
            SILK_INFO << "Lookup txn hash: " << hash.to_hex() << " found in: " << tx_snapshot->path().filename();
            if (settings.print) {
                print_txn(*transaction, tx_snapshot->path().filename());
            }
        } else {
            SILK_WARN << "Lookup txn hash: " << hash.to_hex() << " NOT found in: " << tx_snapshot->path().filename();
        }
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup txn elapsed: " << duration_as<std::chrono::microseconds>(elapsed) << " usec";
}

void lookup_txn_by_hash_in_all(const SnapSettings& settings, const Hash& hash) {
    SnapshotRepository snapshot_repository{settings};
    snapshot_repository.reopen_folder();

    const TransactionSnapshot* matching_snapshot{nullptr};
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    snapshot_repository.view_tx_segments([&](const TransactionSnapshot* snapshot) -> bool {
        const auto transaction{snapshot->txn_by_hash(hash)};
        if (transaction) {
            matching_snapshot = snapshot;
            if (settings.print) {
                print_txn(*transaction, snapshot->path().filename());
            }
        }
        return transaction.has_value();
    });
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup txn elapsed: " << duration_as<std::chrono::microseconds>(elapsed) << " usec";
    if (matching_snapshot) {
        SILK_INFO << "Lookup txn hash: " << hash.to_hex() << " found in: " << matching_snapshot->path().filename();
    } else {
        SILK_WARN << "Lookup txn hash: " << hash.to_hex() << " NOT found";
    }
}

void lookup_txn_by_hash(const SnapSettings& settings, const std::string& lookup_hash) {
    const auto hash{Hash::from_hex(lookup_hash)};
    ensure(hash.has_value(), "lookup_txn_by_hash: lookup_hash is not a valid hash");
    SILK_INFO << "Lookup txn hash: " << hash->to_hex();

    if (settings.snapshot_file_name) {
        lookup_txn_by_hash_in_one(settings, *hash, *settings.snapshot_file_name);
    } else {
        lookup_txn_by_hash_in_all(settings, *hash);
    }
}

void lookup_txn_by_id_in_one(const SnapSettings& settings, uint64_t txn_id, const std::string& file_name) {
    const auto snapshot_path = SnapshotPath::parse(settings.repository_dir / file_name);
    ensure(snapshot_path.has_value(), "lookup_txn_by_id_in_one: --snapshot_file is invalid snapshot file");
    SnapshotRepository snapshot_repository{settings};
    snapshot_repository.reopen_file(*snapshot_path);

    std::chrono::time_point start{std::chrono::steady_clock::now()};
    const auto tx_snapshot{snapshot_repository.get_tx_segment(*snapshot_path)};
    if (tx_snapshot) {
        const auto transaction{tx_snapshot->txn_by_id(txn_id)};
        if (transaction) {
            SILK_INFO << "Lookup txn ID: " << txn_id << " found in: " << tx_snapshot->path().filename();
            if (settings.print) {
                print_txn(*transaction, tx_snapshot->path().filename());
            }
        } else {
            SILK_WARN << "Lookup txn ID: " << txn_id << " NOT found in: " << tx_snapshot->path().filename();
        }
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup txn elapsed: " << duration_as<std::chrono::microseconds>(elapsed) << " usec";
}

void lookup_txn_by_id_in_all(const SnapSettings& settings, uint64_t txn_id) {
    SnapshotRepository snapshot_repository{settings};
    snapshot_repository.reopen_folder();

    const TransactionSnapshot* matching_snapshot{nullptr};
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    snapshot_repository.view_tx_segments([&](const TransactionSnapshot* snapshot) -> bool {
        const auto transaction{snapshot->txn_by_id(txn_id)};
        if (transaction) {
            matching_snapshot = snapshot;
            if (settings.print) {
                print_txn(*transaction, snapshot->path().filename());
            }
        }
        return transaction.has_value();
    });
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup txn elapsed: " << duration_as<std::chrono::milliseconds>(elapsed) << " msec";
    if (matching_snapshot) {
        SILK_INFO << "Lookup txn ID: " << txn_id << " found in: " << matching_snapshot->path().filename();
    } else {
        SILK_WARN << "Lookup txn ID: " << txn_id << " NOT found";
    }
}

void lookup_txn_by_id(const SnapSettings& settings, uint64_t txn_id) {
    SILK_INFO << "Lookup txn ID: " << txn_id;

    if (settings.snapshot_file_name) {
        lookup_txn_by_id_in_one(settings, txn_id, *settings.snapshot_file_name);
    } else {
        lookup_txn_by_id_in_all(settings, txn_id);
    }
}

void lookup_transaction(const SnapSettings& settings) {
    ensure(settings.lookup_hash || settings.lookup_number, "lookup_transaction: either --hash or --number must be used");
    if (settings.lookup_hash) {
        lookup_txn_by_hash(settings, *settings.lookup_hash);
    } else {
        lookup_txn_by_id(settings, *settings.lookup_number);
    }
}

void sync(const SnapSettings& settings) {
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    SnapshotRepository snapshot_repository{settings};
    node::SnapshotSync snapshot_sync{&snapshot_repository, kMainnetConfig};
    std::vector<std::string> snapshot_file_names;
    if (settings.snapshot_file_name) {
        snapshot_file_names.push_back(*settings.snapshot_file_name);
    }
    snapshot_sync.download_snapshots(snapshot_file_names);
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};

    SILK_INFO << "Sync elapsed: " << duration_as<std::chrono::seconds>(elapsed) << " sec";
}

int main(int argc, char* argv[]) {
    CLI::App app{"Snapshots toolbox"};

    try {
        SnapshotToolboxSettings settings;
        parse_command_line(argc, argv, app, settings);

        // Initialize logging with custom settings
        log::init(settings.log_settings);

        const auto pid = boost::this_process::get_id();
        SILK_INFO << "Snapshots toolbox starting [pid=" << std::to_string(pid) << "]";

        const auto node_name{get_node_name_from_build_info(silkworm_get_buildinfo())};
        SILK_INFO << "Snapshots toolbox build info: " << node_name;

        auto command_name = app.get_subcommands().front()->get_name();
        auto tool = magic_enum::enum_cast<SnapshotTool>(command_name).value();

        switch (tool) {
            case SnapshotTool::count_bodies:
                count_bodies(settings.snapshot_settings, settings.repetitions);
                break;
            case SnapshotTool::count_headers:
                count_headers(settings.snapshot_settings, settings.repetitions);
                break;
            case SnapshotTool::create_index:
                create_index(settings.snapshot_settings, settings.repetitions);
                break;
            case SnapshotTool::open_index:
                open_index(settings.snapshot_settings);
                break;
            case SnapshotTool::decode_segment:
                decode_segment(settings.snapshot_settings, settings.repetitions);
                break;
            case SnapshotTool::download:
                download(settings.download_settings);
                break;
            case SnapshotTool::lookup_header:
                lookup_header(settings.snapshot_settings);
                break;
            case SnapshotTool::lookup_body:
                lookup_body(settings.snapshot_settings);
                break;
            case SnapshotTool::lookup_txn:
                lookup_transaction(settings.snapshot_settings);
                break;
            case SnapshotTool::seg_zip:
                seg::seg_zip(settings.snapshot_settings.input_file_path);
                break;
            case SnapshotTool::seg_unzip:
                seg::seg_unzip(settings.snapshot_settings.input_file_path);
                break;
            case SnapshotTool::sync:
                sync(settings.snapshot_settings);
                break;
        }

        SILK_INFO << "Snapshots toolbox exiting [pid=" << std::to_string(pid) << "]";
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
