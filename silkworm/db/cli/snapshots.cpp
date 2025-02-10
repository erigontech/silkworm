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
#include <absl/strings/match.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/process/environment.hpp>
#include <intx/intx.hpp>
#include <magic_enum.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/blocks/bodies/body_queries.hpp>
#include <silkworm/db/blocks/headers/header_index.hpp>
#include <silkworm/db/blocks/headers/header_queries.hpp>
#include <silkworm/db/blocks/schema_config.hpp>
#include <silkworm/db/blocks/transactions/txn_queries.hpp>
#include <silkworm/db/datastore/snapshot_merger.hpp>
#include <silkworm/db/datastore/snapshots/bittorrent/client.hpp>
#include <silkworm/db/datastore/snapshots/bittorrent/web_seed_client.hpp>
#include <silkworm/db/datastore/snapshots/bloom_filter/bloom_filter.hpp>
#include <silkworm/db/datastore/snapshots/btree/btree_index.hpp>
#include <silkworm/db/datastore/snapshots/common/raw_codec.hpp>
#include <silkworm/db/datastore/snapshots/index_salt_file.hpp>
#include <silkworm/db/datastore/snapshots/rec_split/rec_split.hpp>
#include <silkworm/db/datastore/snapshots/segment/seg/seg_zip.hpp>
#include <silkworm/db/datastore/snapshots/segment/segment_reader.hpp>
#include <silkworm/db/datastore/snapshots/snapshot_repository.hpp>
#include <silkworm/db/snapshot_recompress.hpp>
#include <silkworm/db/snapshot_sync.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/cli/common.hpp>
#include <silkworm/infra/cli/shutdown_signal.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/test_util/task_runner.hpp>

using namespace silkworm;
using namespace silkworm::cmd::common;
using namespace silkworm::snapshots;
using namespace silkworm::snapshots::bittorrent;
using namespace silkworm::snapshots::segment;

static constexpr int kDefaultPageSize{4 * 1024};  // 4kB
static constexpr int kDefaultRepetitions{1};

//! The settings for handling Thorax snapshots customized for this tool
struct SnapshotSubcommandSettings {
    SnapshotSettings settings;
    std::filesystem::path input_file_path;
    std::optional<std::string> segment_file_name;
    int page_size{kDefaultPageSize};
    bool skip_system_txs{false};
    std::optional<std::string> lookup_hash;
    std::optional<BlockNum> lookup_block_num;
    bool verbose{false};

    const std::filesystem::path& repository_path() const { return settings.repository_path; }
};

//! The settings for handling BitTorrent protocol customized for this tool
struct DownloadSettings {
    bittorrent::BitTorrentSettings bittorrent_settings;
    ChainId chain_id{kMainnetConfig.chain_id};
    std::string url_seed;
    bool download_web_seed_torrents{false};
    std::optional<std::string> magnet_uri;
};

static const std::filesystem::path kTorrentRepoPath{bittorrent::BitTorrentSettings::kDefaultTorrentRepoPath};

//! The available subcommands in snapshots utility
//! \warning reducing the enum base type size as suggested by clang-tidy breaks CLI11
// NOLINTBEGIN(readability-identifier-naming)
enum class SnapshotTool {  // NOLINT(performance-enum-size)
    count_bodies,
    count_headers,
    create_index,
    open_index,
    open_btree_index,
    open_existence_index,
    decode_segment,
    download,
    lookup_header,
    lookup_body,
    lookup_txn,
    merge,
    recompress,
    seg_zip,
    seg_unzip,
    sync
};
// NOLINTEND(readability-identifier-naming)

//! The overall settings for the snapshot toolbox
struct SnapshotToolboxSettings {
    log::Settings log_settings;
    SnapshotSubcommandSettings snapshot_settings;
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

struct BlockNumValidator : public CLI::Validator {
    explicit BlockNumValidator() {
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
    auto& download_settings = settings.download_settings;
    auto& bittorrent_settings = settings.download_settings.bittorrent_settings;

    add_logging_options(app, log_settings);

    std::map<SnapshotTool, CLI::App*> commands;
    for (auto& [tool, name] : magic_enum::enum_entries<SnapshotTool>()) {
        commands[tool] = app.add_subcommand(std::string{name});
    }
    app.require_subcommand(1);

    app.add_option("--snapshot_dir", snapshot_settings.settings.repository_path, "Path to snapshot repository")
        ->capture_default_str();
    app.add_option("--repetitions", settings.repetitions, "How many times to repeat the execution")
        ->capture_default_str()
        ->check(CLI::Range(1, 100));
    app.add_option("--page", snapshot_settings.page_size, "Page size in kB")
        ->capture_default_str()
        ->check(CLI::Range(1, 1024));
    app.add_flag("--verbose", snapshot_settings.verbose, "Flag indicating if console dump is enabled or not")
        ->capture_default_str();

    for (auto& cmd : {commands[SnapshotTool::lookup_header],
                      commands[SnapshotTool::lookup_body],
                      commands[SnapshotTool::lookup_txn],
                      commands[SnapshotTool::open_index]}) {
        cmd->add_option("--block", snapshot_settings.lookup_block_num, "Block number to lookup in snapshot files")
            ->capture_default_str()
            ->check(BlockNumValidator{});
    }
    for (auto& cmd : {commands[SnapshotTool::lookup_header],
                      commands[SnapshotTool::lookup_body],
                      commands[SnapshotTool::lookup_txn]}) {
        cmd->add_option("--hash", snapshot_settings.lookup_hash, "Hash to lookup in snapshot files")
            ->capture_default_str()
            ->check(HashValidator{});
    }
    for (auto& cmd : {commands[SnapshotTool::download]}) {
        add_option_chain(*cmd, download_settings.chain_id);
        cmd->add_option("--torrent_dir", bittorrent_settings.repository_path, "Path to torrent file repository")
            ->capture_default_str();
        cmd->add_option("--magnet", download_settings.magnet_uri, "Magnet link to download")
            ->capture_default_str();
        cmd->add_option("--url_seed", download_settings.url_seed, "URL seed to download from")
            ->capture_default_str();
        cmd->add_flag("--download_web_seed_torrents",
                      download_settings.download_web_seed_torrents,
                      "Flag indicating if torrents got via URL seed should be downloaded")
            ->capture_default_str();
        cmd->add_option("--download_rate_limit",
                        bittorrent_settings.download_rate_limit,
                        "Download rate limit in bytes per second")
            ->capture_default_str()
            ->check(CLI::Range(4 * 1024 * 1024, 128 * 1024 * 1024));
        cmd->add_option("--upload_rate_limit",
                        bittorrent_settings.upload_rate_limit,
                        "Upload rate limit in bytes per second")
            ->capture_default_str()
            ->check(CLI::Range(1 * 1024 * 1024, 32 * 1024 * 1024));
        cmd->add_option("--active_downloads",
                        bittorrent_settings.active_downloads,
                        "Max number of downloads active simultaneously")
            ->capture_default_str()
            ->check(CLI::Range(3, 20));
    }
    for (auto& cmd : {commands[SnapshotTool::create_index],
                      commands[SnapshotTool::open_index],
                      commands[SnapshotTool::decode_segment]}) {
        cmd->add_option("--snapshot_file", snapshot_settings.segment_file_name, "Path to snapshot file")
            ->required()
            ->capture_default_str();
    }
    for (auto& cmd : {commands[SnapshotTool::count_headers],
                      commands[SnapshotTool::count_bodies],
                      commands[SnapshotTool::lookup_body],
                      commands[SnapshotTool::lookup_header],
                      commands[SnapshotTool::lookup_txn]}) {
        cmd->add_option("--snapshot_file", snapshot_settings.segment_file_name, "Path to snapshot file")
            ->capture_default_str();
    }

    for (auto& cmd : {commands[SnapshotTool::open_btree_index],
                      commands[SnapshotTool::open_existence_index]}) {
        cmd->add_option("--file", snapshot_settings.input_file_path, ".kv file to open with associated .bt file")
            ->required()
            ->check(CLI::ExistingFile);
    }
    commands[SnapshotTool::recompress]
        ->add_option("--file", snapshot_settings.input_file_path, ".seg file to decompress and compress again")
        ->required()
        ->check(CLI::ExistingFile);
    commands[SnapshotTool::seg_zip]
        ->add_option("--file", snapshot_settings.input_file_path, "Raw words file to compress")
        ->required()
        ->check(CLI::ExistingFile);
    commands[SnapshotTool::seg_unzip]
        ->add_option("--file", snapshot_settings.input_file_path, ".seg file to decompress")
        ->required()
        ->check(CLI::ExistingFile);

    app.parse(argc, argv);

    bittorrent_settings.repository_path = snapshot_settings.repository_path() / kTorrentRepoPath;
    snapshot_settings.settings.bittorrent_settings.repository_path = snapshot_settings.repository_path() / kTorrentRepoPath;
}

//! Convert one duration into another one returning the number of ticks for the latter one
//! \param elapsed the duration to convert
template <typename D, typename R, typename P>
auto duration_as(const std::chrono::duration<R, P>& elapsed) {
    return std::chrono::duration_cast<D>(elapsed).count();
}

//! Convert the given duration into milliseconds
//! \param elapsed the duration to convert
template <typename R, typename P>
auto as_milliseconds(const std::chrono::duration<R, P>& elapsed) {
    return duration_as<std::chrono::milliseconds>(elapsed);
}

//! Convert the given duration into seconds
//! \param elapsed the duration to convert
template <typename R, typename P>
auto as_seconds(const std::chrono::duration<R, P>& elapsed) {
    return duration_as<std::chrono::seconds>(elapsed);
}

void decode_segment(const SnapshotSubcommandSettings& settings, int repetitions) {
    ensure(settings.segment_file_name.has_value(), "decode_segment: --snapshot_file must be specified");
    const auto snapshot_path = SnapshotPath::parse(std::filesystem::path{*settings.segment_file_name});
    ensure(snapshot_path.has_value(), "decode_segment: invalid snapshot_file path format");

    SILK_INFO << "Decode snapshot: " << snapshot_path->path();
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    for (int i = 0; i < repetitions; ++i) {
        SegmentFileReader snapshot{*snapshot_path};
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Decode snapshot elapsed: " << as_milliseconds(elapsed) << " msec";
}

static SnapshotRepository make_repository(const SnapshotSettings& settings) {
    return db::blocks::make_blocks_repository(settings.repository_path);
}

using BodyCounters = std::pair<int, uint64_t>;

BodyCounters count_bodies_in_one(const SnapshotSubcommandSettings& settings, const SegmentFileReader& body_segment) {
    int num_bodies = 0;
    uint64_t num_txns = 0;
    constexpr int kFirstItems = 3;
    constexpr int kStepItems = 50'000;
    if (settings.verbose) {
        SILK_INFO << "Printing first " << kFirstItems << " bodies, then every " << kStepItems;
    }
    for (const BlockBodyForStorage& b : BodySegmentReader{body_segment}) {
        // If *system transactions* should not be counted, skip first and last tx in block body
        const auto base_txn_id{settings.skip_system_txs ? b.base_txn_id + 1 : b.base_txn_id};
        const auto txn_count{settings.skip_system_txs && b.txn_count >= 2 ? b.txn_count - 2 : b.txn_count};
        if (settings.verbose && (num_bodies < kFirstItems || num_bodies % kStepItems == 0)) {
            SILK_INFO << "Body number: " << num_bodies << " base_txn_id: " << base_txn_id << " txn_count: " << txn_count
                      << " #ommers: " << b.ommers.size();
        }
        ++num_bodies;
        num_txns += txn_count;
    }
    return {num_bodies, num_txns};
}

BodyCounters count_bodies_in_all(const SnapshotSubcommandSettings& settings) {
    auto repository = make_repository(settings.settings);
    int num_bodies = 0;
    uint64_t num_txns = 0;
    for (const auto& bundle_ptr : repository.view_bundles()) {
        db::blocks::BundleDataRef bundle{**bundle_ptr};
        const auto [body_count, txn_count] = count_bodies_in_one(settings, bundle.body_segment());
        num_bodies += body_count;
        num_txns += txn_count;
    }
    return {num_bodies, num_txns};
}

void count_bodies(const SnapshotSubcommandSettings& settings, int repetitions) {
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    int num_bodies = 0;
    uint64_t num_txns = 0;
    for (int i = 0; i < repetitions; ++i) {
        if (settings.segment_file_name) {
            const auto snapshot_path{SnapshotPath::parse(std::filesystem::path{*settings.segment_file_name})};
            ensure(snapshot_path.has_value(), "count_bodies: invalid snapshot_file path format");
            SegmentFileReader body_segment{*snapshot_path};
            std::tie(num_bodies, num_txns) = count_bodies_in_one(settings, body_segment);
        } else {
            std::tie(num_bodies, num_txns) = count_bodies_in_all(settings);
        }
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "How many bodies: " << num_bodies << " txs: " << num_txns << " duration: " << as_milliseconds(elapsed) << " msec";
}

int count_headers_in_one(const SnapshotSubcommandSettings& settings, const SegmentFileReader& header_segment) {
    int num_headers = 0;
    constexpr int kFirstItems = 3;
    constexpr int kStepItems = 50'000;
    if (settings.verbose) {
        SILK_INFO << "Printing first " << kFirstItems << " headers, then every " << kStepItems;
    }
    for (const BlockHeader& h : HeaderSegmentReader{header_segment}) {
        ++num_headers;
        if (settings.verbose && (num_headers < kFirstItems || num_headers % kStepItems == 0)) {
            SILK_INFO << "Header number: " << h.number << " hash: " << to_hex(h.hash());
        }
    }
    return num_headers;
}

int count_headers_in_all(const SnapshotSubcommandSettings& settings) {
    auto repository = make_repository(settings.settings);
    int num_headers{0};
    for (const auto& bundle_ptr : repository.view_bundles()) {
        db::blocks::BundleDataRef bundle{**bundle_ptr};
        const auto header_count = count_headers_in_one(settings, bundle.header_segment());
        num_headers += header_count;
    }
    return num_headers;
}

void count_headers(const SnapshotSubcommandSettings& settings, int repetitions) {
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    int num_headers{0};
    for (int i{0}; i < repetitions; ++i) {
        if (settings.segment_file_name) {
            const auto snapshot_path{SnapshotPath::parse(std::filesystem::path{*settings.segment_file_name})};
            ensure(snapshot_path.has_value(), "count_headers: invalid snapshot_file path format");
            SegmentFileReader header_segment{*snapshot_path};
            num_headers = count_headers_in_one(settings, header_segment);
        } else {
            num_headers = count_headers_in_all(settings);
        }
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    const auto duration = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    SILK_INFO << "How many headers: " << num_headers << " duration: " << duration << " msec";
}

void create_index(const SnapshotSubcommandSettings& settings, int repetitions) {
    ensure(settings.segment_file_name.has_value(), "create_index: --snapshot_file must be specified");
    SILK_INFO << "Create index for snapshot: " << *settings.segment_file_name;
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    auto index_builders_factory = db::blocks::make_blocks_index_builders_factory();
    const auto snapshot_path = SnapshotPath::parse(std::filesystem::path{*settings.segment_file_name});
    if (snapshot_path) {
        for (int i{0}; i < repetitions; ++i) {
            for (auto& builder : index_builders_factory->index_builders(*snapshot_path)) {
                builder->build();
            }
        }
    } else {
        SILK_ERROR << "Invalid snapshot file: " << *settings.segment_file_name;
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Create index elapsed: " << as_milliseconds(elapsed) << " msec";
}

void open_index(const SnapshotSubcommandSettings& settings) {
    ensure(settings.segment_file_name.has_value(), "open_index: --snapshot_file must be specified");
    std::filesystem::path segment_file_path{settings.repository_path() / *settings.segment_file_name};
    SILK_INFO << "Open index for snapshot: " << segment_file_path;
    const auto snapshot_path{snapshots::SnapshotPath::parse(segment_file_path)};
    ensure(snapshot_path.has_value(), [&]() { return "open_index: invalid snapshot file " + segment_file_path.filename().string(); });
    const auto index_path{snapshot_path->related_path_ext(db::blocks::kIdxExtension)};
    SILK_INFO << "Index file: " << index_path.path();
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    rec_split::RecSplitIndex idx{index_path.path()};
    SILK_INFO << "Index properties: empty=" << idx.empty() << " base_data_id=" << idx.base_data_id()
              << " double_enum_index=" << idx.double_enum_index() << " less_false_positives=" << idx.less_false_positives();
    if (idx.double_enum_index()) {
        if (settings.lookup_block_num) {
            const uint64_t data_id{*settings.lookup_block_num};
            auto offset = idx.lookup_by_data_id(data_id);
            if (offset) {
                SILK_INFO << "Offset by data id lookup for " << data_id << ": " << *offset;
            } else {
                SILK_WARN << "Invalid data id " << data_id;
            }
        } else {
            for (size_t i{0}; i < idx.key_count(); ++i) {
                if (i % (idx.key_count() / 10) == 0) {
                    SILK_INFO << "Offset by ordinal lookup for " << i << ": " << idx.lookup_by_ordinal({i})
                              << " [existence filter: " << int{idx.existence_filter()[i]} << "]";
                }
            }
        }
    } else {
        SILK_INFO << "Index does not support 2-layer enum indexing";
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Open index elapsed: " << as_milliseconds(elapsed) << " msec";
}

void open_btree_index(const SnapshotSubcommandSettings& settings) {
    ensure(!settings.input_file_path.empty(), "open_btree_index: --file must be specified");
    ensure(settings.input_file_path.extension() == ".kv", "open_btree_index: --file must be .kv file");

    auto kv_segment_path = SnapshotPath::parse(settings.input_file_path);
    ensure(kv_segment_path.has_value(), "open_btree_index: invalid input file name format");

    auto bt_index_path = kv_segment_path->related_path_ext(".bt");
    SILK_INFO << "KV file: " << kv_segment_path->path().string()
              << " BT file: " << bt_index_path.path().string();

    std::chrono::time_point start{std::chrono::steady_clock::now()};

    segment::KVSegmentFileReader kv_segment{*kv_segment_path, seg::CompressionKind::kAll};

    btree::BTreeIndex bt_index{bt_index_path.path()};
    SILK_INFO << "Starting KV scan and BTreeIndex check, total keys: " << bt_index.key_count();

    segment::KVSegmentReader<RawDecoder<Bytes>, RawDecoder<Bytes>> reader{kv_segment};
    size_t matching_count{0}, key_count{0};
    for (auto kv_pair : reader) {
        ByteView key = kv_pair.first;
        ByteView value = kv_pair.second;

        const auto v = bt_index.get(key, kv_segment);
        SILK_DEBUG << "KV: key=" << to_hex(key) << " value=" << to_hex(value) << " v=" << (v ? to_hex(*v) : "");
        ensure(v == value, [&]() {
            return "open_btree_index: value mismatch for key=" + to_hex(key) +
                   " position=" + std::to_string(key_count);
        });
        if (v == value) {
            ++matching_count;
        }

        ++key_count;
        if (key_count % 10'000'000 == 0) {
            SILK_INFO << "BTreeIndex check progress: " << key_count << " different: " << (key_count - matching_count);
        }
    }

    ensure(key_count == bt_index.key_count(), "open_btree_index: total key count does not match");
    SILK_INFO << "Open btree index matching: " << matching_count << " different: " << (key_count - matching_count);
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Open btree index elapsed: " << as_milliseconds(elapsed) << " msec";
}

void open_existence_index(const SnapshotSubcommandSettings& settings) {
    ensure(!settings.input_file_path.empty(), "open_existence_index: --file must be specified");
    ensure(settings.input_file_path.extension() == ".kv", "open_existence_index: --file must be .kv file");
    const auto is_file_for_domain = [](const auto& file_path, auto domain_name) -> bool {
        return absl::StrContains(file_path.filename().string(), domain_name);
    };
    const bool is_account_file = is_file_for_domain(settings.input_file_path, db::table::kAccountDomain);
    ensure(is_account_file, "open_existence_index: --file must be an accounts .kv file (e.g. v1-accounts.0-1024.kv)");

    std::filesystem::path existence_index_file_path = settings.input_file_path;
    existence_index_file_path.replace_extension(".kvei");
    SILK_INFO << "KV file: " << settings.input_file_path.string() << " KVEI file: " << existence_index_file_path.string();

    const auto salt_path = existence_index_file_path.parent_path().parent_path() / "salt-state.txt";
    snapshots::IndexSaltFile salt_file{salt_path};
    const uint32_t salt = salt_file.load();
    SILK_INFO << "Snapshot salt " << salt << " from " << salt_path.filename().string();

    std::chrono::time_point start{std::chrono::steady_clock::now()};
    seg::Decompressor kv_decompressor{settings.input_file_path};
    bloom_filter::BloomFilter existence_index{existence_index_file_path, bloom_filter::BloomFilterKeyHasher{salt}};

    SILK_INFO << "Starting KV scan and existence index check";
    size_t key_count{0}, found_count{0}, nonexistent_count{0}, nonexistent_found_count{0};
    bool is_key{true};
    Bytes previous_key, key, value;
    auto kv_iterator = kv_decompressor.begin();
    while (kv_iterator != kv_decompressor.end()) {
        // KV files contain alternated keys and values: k1|v1|...|kN|vN
        if (is_key) {
            previous_key = key;
            key = *kv_iterator;
            // Check if there's any gap between adjacent keys in KV file: if so, we have nonexistent keys to check
            const auto previous = intx::from_string<intx::uint256>(to_hex(previous_key, /*with_prefix=*/true));
            const auto current = intx::from_string<intx::uint256>(to_hex(key, /*with_prefix=*/true));
            if (key_count > 0 && current > previous + 1) {
                // We pick just one nonexistent key for each gap
                ++nonexistent_count;
                const intx::uint256 nonexistent = previous + 1;
                // Prepare the nonexistent key
                uint8_t full_be[sizeof(intx::uint256)];
                intx::be::store(full_be, nonexistent);
                constexpr ptrdiff_t kSizeDiff = sizeof(intx::uint256) - sizeof(evmc::address);
                ByteView nonexistent_key = {full_be + kSizeDiff, sizeof(intx::uint256) - kSizeDiff};
                SILK_TRACE << "KV: previous_key=" << to_hex(previous_key) << " key=" << to_hex(key)
                           << " nonexistent_key=" << to_hex(nonexistent_key);
                if (existence_index.contains(nonexistent_key)) {
                    ++nonexistent_found_count;
                }
            }
            ++key_count;
        } else {
            value = *kv_iterator;
            SILK_DEBUG << "KV: key=" << to_hex(key) << " value=" << to_hex(value);
            ensure(existence_index.contains(key),
                   [&]() { return "open_existence_index: unexpected not found key=" + to_hex(key) +
                                  " position=" + std::to_string(key_count); });
            ++found_count;
            if (key_count % 10'000'000 == 0) {
                const float false_pos_rate = static_cast<float>(nonexistent_found_count) / static_cast<float>(nonexistent_count);
                SILK_INFO << "Existence index check progress: " << key_count << " non-existent: " << nonexistent_count
                          << " false positive rate: " << false_pos_rate;
            }
        }
        ++kv_iterator;
        is_key = !is_key;
    }
    ensure(found_count == key_count,
           [&]() { return "open_existence_index: found count " + std::to_string(found_count) + ", key count " + std::to_string(key_count); });
    const float false_pos_rate = static_cast<float>(nonexistent_found_count) / static_cast<float>(nonexistent_count);
    SILK_INFO << "Open existence index keys: " << key_count << " non-existent: " << nonexistent_count << " false positives: " << false_pos_rate;
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Open existence index elapsed: " << as_milliseconds(elapsed) << " msec";
}

static TorrentInfoPtrList download_web_seed(const DownloadSettings& settings) {
    using namespace silkworm::concurrency::awaitable_wait_for_one;

    const auto known_config{snapshots::Config::lookup_known_config(settings.chain_id)};
    WebSeedClient web_client{/*url_seeds=*/{settings.url_seed}, known_config.preverified_snapshots_as_pairs()};

    boost::asio::io_context ioc;

    TorrentInfoPtrList torrent_info_list;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-capturing-lambda-coroutines)
    auto discover_torrent_and_stop = [&]() -> Task<void> {
        try {
            torrent_info_list = co_await web_client.discover_torrents(/*fail_fast=*/true);
        } catch (const boost::system::system_error& se) {
            SILK_ERROR << "Cannot discover torrents at " + settings.url_seed + ": " + se.what();
        }
        ioc.stop();
    };

    boost::asio::co_spawn(ioc, discover_torrent_and_stop() || ShutdownSignal::wait(), boost::asio::use_future);
    ioc.run();

    size_t i{0};
    for (const auto& torrent_info : torrent_info_list) {
        SILK_INFO << i++ << ") name: " << torrent_info->name() << " hash: " << torrent_info->info_hash();
    }
    return torrent_info_list;
}

static void download_bittorrent(bittorrent::BitTorrentClient& client) {
    using namespace silkworm::concurrency::awaitable_wait_for_one;
    SILK_INFO << "Bittorrent download started in repo: " << client.settings().repository_path.string();

    boost::asio::io_context ioc;
    boost::asio::co_spawn(ioc, client.async_run("bit-torrent") || ShutdownSignal::wait(), boost::asio::use_future);
    ioc.run();
}

void download(const DownloadSettings& settings) {
    std::chrono::time_point start{std::chrono::steady_clock::now()};

    if (!settings.url_seed.empty()) {
        // Download the torrent files via web seeding from settings.url_seed
        bittorrent::TorrentInfoPtrList web_seed_torrents = download_web_seed(settings);

        // Optionally download also the target files by using the torrents just downloaded
        if (settings.download_web_seed_torrents) {
            bittorrent::BitTorrentClient client{settings.bittorrent_settings};
            for (auto it = web_seed_torrents.begin(); it != web_seed_torrents.end(); it = web_seed_torrents.erase(it)) {
                client.add_torrent_info(*it);
            }
            download_bittorrent(client);
        }
    } else if (settings.magnet_uri) {
        // Download the magnet link
        bittorrent::BitTorrentClient client{settings.bittorrent_settings};
        SILK_INFO << "Bittorrent async download started for magnet file: " << *settings.magnet_uri;
        client.add_magnet_uri(*settings.magnet_uri);
        download_bittorrent(client);
        SILK_INFO << "Bittorrent async download completed for magnet file: " << *settings.magnet_uri;
    } else {
        SILK_WARN << "No download source. Pass either --url_seed or --magnet";
        return;
    }

    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Download elapsed: " << as_seconds(elapsed) << " sec";
}

static void print_header(const BlockHeader& header, const std::string& filename) {
    std::cout << "Header found in: " << filename << "\n"
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

void lookup_header_by_hash(const SnapshotSubcommandSettings& settings) {
    const auto hash{Hash::from_hex(*settings.lookup_hash)};
    ensure(hash.has_value(), "lookup_header_by_hash: lookup_hash is not a valid hash");
    SILK_INFO << "Lookup header hash: " << hash->to_hex();
    std::chrono::time_point start{std::chrono::steady_clock::now()};

    std::optional<SnapshotPath> matching_snapshot_path;
    std::optional<BlockHeader> matching_header;
    auto repository = make_repository(settings.settings);
    for (const auto& bundle_ptr : repository.view_bundles_reverse()) {
        const auto& bundle = *bundle_ptr;
        auto segment_and_index = bundle.segment_and_accessor_index(db::blocks::kHeaderSegmentAndIdxNames);
        const auto header = HeaderFindByHashSegmentQuery{segment_and_index}.exec(*hash);
        if (header) {
            matching_header = header;
            matching_snapshot_path = segment_and_index.segment.path();
            break;
        }
    }
    if (matching_snapshot_path) {
        SILK_INFO << "Lookup header hash: " << hash->to_hex() << " found in: " << matching_snapshot_path->filename();
        if (matching_header && settings.verbose) {
            print_header(*matching_header, matching_snapshot_path->filename());
        }
    } else {
        SILK_WARN << "Lookup header hash: " << hash->to_hex() << " NOT found";
    }

    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup header elapsed: " << as_milliseconds(elapsed) << " msec";
}

void lookup_header_by_number(const SnapshotSubcommandSettings& settings) {
    const auto block_num{*settings.lookup_block_num};
    SILK_INFO << "Lookup header number: " << block_num;
    std::chrono::time_point start{std::chrono::steady_clock::now()};

    auto repository = make_repository(settings.settings);
    const auto [segment_and_index, _] = repository.find_segment(db::blocks::kHeaderSegmentAndIdxNames, block_num);
    if (segment_and_index) {
        const auto header = HeaderFindByBlockNumSegmentQuery{*segment_and_index}.exec(block_num);
        ensure(header.has_value(),
               [&]() { return "lookup_header_by_number: " + std::to_string(block_num) + " NOT found in " + segment_and_index->segment.path().filename(); });
        SILK_INFO << "Lookup header number: " << block_num << " found in: " << segment_and_index->segment.path().filename();
        if (settings.verbose) {
            print_header(*header, segment_and_index->segment.path().filename());
        }
    } else {
        SILK_WARN << "Lookup header number: " << block_num << " NOT found";
    }

    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup header elapsed: " << as_milliseconds(elapsed) << " msec";
}

void lookup_header(const SnapshotSubcommandSettings& settings) {
    ensure(settings.lookup_hash || settings.lookup_block_num, "lookup_header: either --hash or --block must be used");
    if (settings.lookup_hash) {
        lookup_header_by_hash(settings);
    } else {
        lookup_header_by_number(settings);
    }
}

static void print_body(const BlockBodyForStorage& body, const std::string& filename) {
    std::cout << "Body found in: " << filename << "\n"
              << "base_txn_id=" << body.base_txn_id << "\n"
              << "txn_count=" << body.txn_count << "\n"
              << "rlp=" << to_hex(body.encode()) << "\n";
}

void lookup_body_in_one(const SnapshotSubcommandSettings& settings, BlockNum block_num, const std::string& file_name) {
    const auto snapshot_path = SnapshotPath::parse(settings.repository_path() / file_name);
    ensure(snapshot_path.has_value(), "lookup_body: --snapshot_file is invalid snapshot file");

    std::chrono::time_point start{std::chrono::steady_clock::now()};
    SegmentFileReader body_segment{*snapshot_path};

    rec_split::AccessorIndex idx_body_number{snapshot_path->related_path_ext(db::blocks::kIdxExtension)};

    const auto body = BodyFindByBlockNumSegmentQuery{{body_segment, idx_body_number}}.exec(block_num);
    if (body) {
        SILK_INFO << "Lookup body number: " << block_num << " found in: " << body_segment.path().filename();
        if (settings.verbose) {
            print_body(*body, body_segment.path().filename());
        }
    } else {
        SILK_WARN << "Lookup body number: " << block_num << " NOT found in: " << body_segment.path().filename();
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup body elapsed: " << duration_as<std::chrono::microseconds>(elapsed) << " usec";
}

void lookup_body_in_all(const SnapshotSubcommandSettings& settings, BlockNum block_num) {
    auto repository = make_repository(settings.settings);

    std::chrono::time_point start{std::chrono::steady_clock::now()};
    const auto [segment_and_index, _] = repository.find_segment(db::blocks::kBodySegmentAndIdxNames, block_num);
    if (segment_and_index) {
        const auto body = BodyFindByBlockNumSegmentQuery{*segment_and_index}.exec(block_num);
        ensure(body.has_value(),
               [&]() { return "lookup_body: " + std::to_string(block_num) + " NOT found in " + segment_and_index->segment.path().filename(); });
        SILK_INFO << "Lookup body number: " << block_num << " found in: " << segment_and_index->segment.path().filename();
        if (settings.verbose) {
            print_body(*body, segment_and_index->segment.path().filename());
        }
    } else {
        SILK_WARN << "Lookup body number: " << block_num << " NOT found";
    }

    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup header elapsed: " << duration_as<std::chrono::microseconds>(elapsed) << " usec";
}

void lookup_body(const SnapshotSubcommandSettings& settings) {
    ensure(settings.lookup_block_num.has_value(), "lookup_body: --block must be specified");
    const auto block_num{*settings.lookup_block_num};
    SILK_INFO << "Lookup body number: " << block_num;

    if (settings.segment_file_name) {
        lookup_body_in_one(settings, block_num, *settings.segment_file_name);
    } else {
        lookup_body_in_all(settings, block_num);
    }
}

static void print_txn(const Transaction& txn, const std::string& filename) {
    std::cout << "Transaction found in: " << filename << "\n"
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
              << "authorizations=" << ([&]() {
                     std::string rep{"["};
                     for (size_t i{0}; i < txn.authorizations.size(); ++i) {
                         const auto& authorization{txn.authorizations[i]};
                         rep.append(intx::to_string(authorization.chain_id));
                         rep.append(address_to_hex(authorization.address));
                         rep.append(std::to_string(authorization.nonce));
                         rep.append(std::to_string(authorization.y_parity));
                         rep.append(intx::to_string(authorization.r));
                         rep.append(intx::to_string(authorization.s));
                         if (i != txn.authorizations.size() - 1) rep.append("], ");
                     }
                     rep.append("]");
                     return rep;
                 }())
              << "\n"
              << "rlp=" << to_hex([&]() { Bytes b; rlp::encode(b, txn); return b; }()) << "\n";
}

void lookup_txn_by_hash_in_one(const SnapshotSubcommandSettings& settings, const Hash& hash, const std::string& file_name) {
    const auto snapshot_path = SnapshotPath::parse(settings.repository_path() / file_name);
    ensure(snapshot_path.has_value(), "lookup_tx_by_hash_in_one: --snapshot_file is invalid snapshot file");

    std::chrono::time_point start{std::chrono::steady_clock::now()};
    SegmentFileReader txn_segment{*snapshot_path};

    {
        rec_split::AccessorIndex idx_txn_hash{snapshot_path->related_path_ext(db::blocks::kIdxExtension)};

        const auto transaction = TransactionFindByHashSegmentQuery{{txn_segment, idx_txn_hash}}.exec(hash);
        if (transaction) {
            SILK_INFO << "Lookup txn hash: " << hash.to_hex() << " found in: " << txn_segment.path().filename();
            if (settings.verbose) {
                print_txn(*transaction, txn_segment.path().filename());
            }
        } else {
            SILK_WARN << "Lookup txn hash: " << hash.to_hex() << " NOT found in: " << txn_segment.path().filename();
        }
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup txn elapsed: " << duration_as<std::chrono::microseconds>(elapsed) << " usec";
}

void lookup_txn_by_hash_in_all(const SnapshotSubcommandSettings& settings, const Hash& hash) {
    auto repository = make_repository(settings.settings);

    std::optional<SnapshotPath> matching_snapshot_path;
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    for (const auto& bundle_ptr : repository.view_bundles_reverse()) {
        const auto& bundle = *bundle_ptr;
        auto segment_and_index = bundle.segment_and_accessor_index(db::blocks::kTxnSegmentAndIdxNames);
        const auto transaction = TransactionFindByHashSegmentQuery{segment_and_index}.exec(hash);
        if (transaction) {
            matching_snapshot_path = segment_and_index.segment.path();
            if (settings.verbose) {
                print_txn(*transaction, matching_snapshot_path->path().filename());
            }
            break;
        }
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup txn elapsed: " << duration_as<std::chrono::microseconds>(elapsed) << " usec";
    if (matching_snapshot_path) {
        SILK_INFO << "Lookup txn hash: " << hash.to_hex() << " found in: " << matching_snapshot_path->path().filename();
    } else {
        SILK_WARN << "Lookup txn hash: " << hash.to_hex() << " NOT found";
    }
}

void lookup_txn_by_hash(const SnapshotSubcommandSettings& settings, const std::string& lookup_hash) {
    const auto hash{Hash::from_hex(lookup_hash)};
    ensure(hash.has_value(), "lookup_txn_by_hash: lookup_hash is not a valid hash");
    SILK_INFO << "Lookup txn hash: " << hash->to_hex();

    if (settings.segment_file_name) {
        lookup_txn_by_hash_in_one(settings, *hash, *settings.segment_file_name);
    } else {
        lookup_txn_by_hash_in_all(settings, *hash);
    }
}

void lookup_txn_by_id_in_one(const SnapshotSubcommandSettings& settings, uint64_t txn_id, const std::string& file_name) {
    const auto snapshot_path = SnapshotPath::parse(settings.repository_path() / file_name);
    ensure(snapshot_path.has_value(), "lookup_txn_by_id_in_one: --snapshot_file is invalid snapshot file");

    std::chrono::time_point start{std::chrono::steady_clock::now()};
    SegmentFileReader txn_segment{*snapshot_path};

    {
        rec_split::AccessorIndex idx_txn_hash{snapshot_path->related_path_ext(db::blocks::kIdxExtension)};

        const auto transaction = TransactionFindByIdSegmentQuery{{txn_segment, idx_txn_hash}}.exec(txn_id);
        if (transaction) {
            SILK_INFO << "Lookup txn ID: " << txn_id << " found in: " << txn_segment.path().filename();
            if (settings.verbose) {
                print_txn(*transaction, txn_segment.path().filename());
            }
        } else {
            SILK_WARN << "Lookup txn ID: " << txn_id << " NOT found in: " << txn_segment.path().filename();
        }
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup txn elapsed: " << duration_as<std::chrono::microseconds>(elapsed) << " usec";
}

void lookup_txn_by_id_in_all(const SnapshotSubcommandSettings& settings, uint64_t txn_id) {
    auto repository = make_repository(settings.settings);

    std::optional<SnapshotPath> matching_snapshot_path;
    std::chrono::time_point start{std::chrono::steady_clock::now()};
    for (const auto& bundle_ptr : repository.view_bundles_reverse()) {
        const auto& bundle = *bundle_ptr;
        auto segment_and_index = bundle.segment_and_accessor_index(db::blocks::kTxnSegmentAndIdxNames);
        const auto transaction = TransactionFindByIdSegmentQuery{segment_and_index}.exec(txn_id);
        if (transaction) {
            matching_snapshot_path = segment_and_index.segment.path();
            if (settings.verbose) {
                print_txn(*transaction, matching_snapshot_path->path().filename());
            }
            break;
        }
    }
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};
    SILK_INFO << "Lookup txn elapsed: " << as_milliseconds(elapsed) << " msec";
    if (matching_snapshot_path) {
        SILK_INFO << "Lookup txn ID: " << txn_id << " found in: " << matching_snapshot_path->path().filename();
    } else {
        SILK_WARN << "Lookup txn ID: " << txn_id << " NOT found";
    }
}

void lookup_txn_by_id(const SnapshotSubcommandSettings& settings, uint64_t txn_id) {
    SILK_INFO << "Lookup txn ID: " << txn_id;

    if (settings.segment_file_name) {
        lookup_txn_by_id_in_one(settings, txn_id, *settings.segment_file_name);
    } else {
        lookup_txn_by_id_in_all(settings, txn_id);
    }
}

void lookup_transaction(const SnapshotSubcommandSettings& settings) {
    ensure(settings.lookup_hash || settings.lookup_block_num, "lookup_transaction: either --hash or --block must be used");
    if (settings.lookup_hash) {
        lookup_txn_by_hash(settings, *settings.lookup_hash);
    } else {
        lookup_txn_by_id(settings, *settings.lookup_block_num);
    }
}

void merge(const SnapshotSettings& settings) {
    auto repository = make_repository(settings);
    TemporaryDirectory tmp_dir;
    datastore::SnapshotMerger merger{repository, tmp_dir.path()};
    test_util::TaskRunner runner;
    runner.run(merger.exec());
}

void sync(const SnapshotSettings& settings) {
    class NoopStageSchedulerAdapter : public datastore::StageScheduler {
      public:
        explicit NoopStageSchedulerAdapter() = default;
        ~NoopStageSchedulerAdapter() override = default;
        Task<void> schedule(std::function<void(db::RWTxn&)> /*callback*/) override {
            co_return;
        }
    };

    std::chrono::time_point start{std::chrono::steady_clock::now()};

    TemporaryDirectory tmp_dir;
    datastore::kvdb::EnvConfig chaindata_env_config{tmp_dir.path()};

    db::DataStore data_store{
        chaindata_env_config,
        settings.repository_path,
    };

    test_util::TaskRunner runner;
    NoopStageSchedulerAdapter stage_scheduler;
    db::SnapshotSync snapshot_sync{
        settings,
        kMainnetConfig.chain_id,
        data_store.ref(),
        tmp_dir.path(),
        stage_scheduler,
    };
    runner.run(snapshot_sync.download_snapshots());
    std::chrono::duration elapsed{std::chrono::steady_clock::now() - start};

    SILK_INFO << "Sync elapsed: " << as_seconds(elapsed) << " sec";
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
            case SnapshotTool::open_btree_index:
                open_btree_index(settings.snapshot_settings);
                break;
            case SnapshotTool::open_existence_index:
                open_existence_index(settings.snapshot_settings);
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
            case SnapshotTool::merge:
                merge(settings.snapshot_settings.settings);
                break;
            case SnapshotTool::recompress:
                snapshot_file_recompress(settings.snapshot_settings.input_file_path);
                break;
            case SnapshotTool::seg_zip:
                seg::seg_zip(settings.snapshot_settings.input_file_path);
                break;
            case SnapshotTool::seg_unzip:
                seg::seg_unzip(settings.snapshot_settings.input_file_path);
                break;
            case SnapshotTool::sync:
                sync(settings.snapshot_settings.settings);
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
