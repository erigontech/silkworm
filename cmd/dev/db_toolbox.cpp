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

#include <algorithm>
#include <bit>
#include <bitset>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>

#include <CLI/CLI.hpp>
#include <boost/format.hpp>
#include <magic_enum.hpp>
#include <tl/expected.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/trie/nibbles.hpp>
#include <silkworm/core/trie/prefix_set.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>
#include <silkworm/node/db/genesis.hpp>
#include <silkworm/node/db/mdbx.hpp>
#include <silkworm/node/db/prune_mode.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>
#include <silkworm/node/stagedsync/stages/stage_interhashes/trie_cursor.hpp>

namespace fs = std::filesystem;
using namespace silkworm;

class Progress {
  public:
    explicit Progress(uint32_t width) : bar_width_{width}, percent_step_{100u / width} {};
    ~Progress() = default;

    //! Returns current progress percent
    [[nodiscard]] uint32_t percent() const {
        if (!max_counter_) {
            return 100;
        }
        if (!current_counter_) {
            return 0;
        }
        return static_cast<uint32_t>(current_counter_ * 100 / max_counter_);
    }

    void step() { current_counter_++; }
    void set_current(size_t count) { current_counter_ = std::max(count, current_counter_); }
    [[nodiscard]] size_t get_current() const noexcept { return current_counter_; }
    [[nodiscard]] size_t get_increment_count() const noexcept { return bar_width_ ? (max_counter_ / bar_width_) : 0u; }

    void reset() {
        current_counter_ = 0;
        printed_bar_len_ = 0;
    }
    void set_task_count(size_t iterations) {
        reset();
        max_counter_ = iterations;
    }

    //! Prints progress ticks
    std::string print_interval(char c = '.') {
        uint32_t percentage{std::min(percent(), 100u)};
        uint32_t numChars{percentage / percent_step_};
        if (!numChars) return "";
        uint32_t intChars{numChars - printed_bar_len_};
        if (!intChars) return "";
        std::string ret(intChars, c);
        printed_bar_len_ += intChars;
        return ret;
    }

    [[maybe_unused]] [[nodiscard]] std::string print_progress(char c = '.') const {
        uint32_t percentage{percent()};
        uint32_t numChars{percentage / percent_step_};
        if (!numChars) {
            return "";
        }
        std::string ret(numChars, c);
        return ret;
    }

  private:
    uint32_t bar_width_;
    uint32_t percent_step_;
    size_t max_counter_{0};
    size_t current_counter_{0};
    uint32_t printed_bar_len_{0};
};

struct DbTableInfo {
    MDBX_dbi id{0};
    std::string name{};
    mdbx::txn::map_stat stat;
    mdbx::map_handle::info info;
    [[nodiscard]] size_t pages() const noexcept {
        return stat.ms_branch_pages + stat.ms_leaf_pages + stat.ms_overflow_pages;
    }
    [[nodiscard]] size_t size() const noexcept { return pages() * stat.ms_psize; }
};

[[nodiscard]] bool operator==(const DbTableInfo& lhs, const DbTableInfo& rhs) {
    return lhs.name == rhs.name;
}

using DbComparisonResult = tl::expected<void, std::string>;

[[nodiscard]] DbComparisonResult compare(const DbTableInfo& lhs, const DbTableInfo& rhs, bool check_pages) {
    // Skip freelist table because its content depends not only on *which* data you write but also *how* you write it
    // (i.e. writing the same data w/ different commit policies can lead to different freelist content)
    if (lhs.name == "FREE_DBI" && rhs.name == "FREE_DBI") {
        return {};
    }

    if (lhs.name != rhs.name) {
        return tl::make_unexpected("name mismatch: " + lhs.name + " vs " + rhs.name);
    }
    if (lhs.stat.ms_entries != rhs.stat.ms_entries) {
        return tl::make_unexpected("num records mismatch: " + std::to_string(lhs.stat.ms_entries) +
                                   " vs " + std::to_string(rhs.stat.ms_entries));
    }
    if (lhs.stat.ms_depth != rhs.stat.ms_depth) {
        return tl::make_unexpected("btree height mismatch: " + std::to_string(lhs.stat.ms_depth) +
                                   " vs " + std::to_string(rhs.stat.ms_depth));
    }
    if (lhs.stat.ms_psize != rhs.stat.ms_psize) {
        return tl::make_unexpected("db page mismatch: " + std::to_string(lhs.stat.ms_psize) +
                                   " vs " + std::to_string(rhs.stat.ms_psize));
    }
    if (lhs.info.flags != rhs.info.flags) {
        return tl::make_unexpected("flags mismatch: " + std::to_string(lhs.info.flags) + " vs " + std::to_string(rhs.info.flags));
    }
    if (check_pages) {
        if (lhs.stat.ms_leaf_pages != rhs.stat.ms_leaf_pages) {
            return tl::make_unexpected("leaf pages mismatch: " + std::to_string(lhs.stat.ms_leaf_pages) +
                                       " vs " + std::to_string(rhs.stat.ms_leaf_pages));
        }
        if (lhs.stat.ms_branch_pages != rhs.stat.ms_branch_pages) {
            return tl::make_unexpected("branch pages mismatch: " + std::to_string(lhs.stat.ms_branch_pages) +
                                       " vs " + std::to_string(rhs.stat.ms_branch_pages));
        }
        if (lhs.stat.ms_overflow_pages != rhs.stat.ms_overflow_pages) {
            return tl::make_unexpected("overflow pages mismatch: " + std::to_string(lhs.stat.ms_overflow_pages) +
                                       " vs " + std::to_string(rhs.stat.ms_overflow_pages));
        }
    }
    return {};
}

struct DbInfo {
    size_t file_size{0};
    size_t page_size{0};
    size_t pages{0};
    size_t size{0};
    std::vector<DbTableInfo> tables{};
};

struct DbFreeEntry {
    size_t id{0};
    size_t pages{0};
    size_t size{0};
};

struct DbFreeInfo {
    size_t pages{0};
    size_t size{0};
    std::vector<DbFreeEntry> entries{};
};

void cursor_for_each(mdbx::cursor& cursor, db::WalkFuncRef walker) {
    const bool throw_notfound{false};
    auto data = cursor.eof() ? cursor.to_first(throw_notfound) : cursor.current(throw_notfound);
    while (data) {
        walker(db::from_slice(data.key), db::from_slice(data.value));
        data = cursor.move(mdbx::cursor::move_operation::next, throw_notfound);
    }
}

static void print_header(const BlockHeader& header) {
    std::cout << "Header:\nhash=" << to_hex(header.hash()) << "\n"
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

static void print_body(const db::detail::BlockBodyForStorage& body) {
    std::cout << "Body:\nbase_txn_id=" << body.base_txn_id << "\n"
              << "txn_count=" << body.txn_count << "\n"
              << "#ommers=" << body.ommers.size() << "\n"
              << (body.withdrawals ? "#withdrawals=" + std::to_string(body.withdrawals->size()) + "\n" : "")
              << "rlp=" << to_hex(body.encode()) << "\n";
}

bool user_confirmation(const std::string& message = {"Confirm ?"}) {
    static std::regex pattern{"^([yY])?([nN])?$"};
    std::smatch matches;

    std::string user_input;
    do {
        std::cout << "\n"
                  << message << " [y/N] ";
        std::cin >> user_input;
        std::cin.clear();
        if (std::regex_search(user_input, matches, pattern, std::regex_constants::match_default)) {
            break;
        }
        std::cout << "Hmmm... maybe you didn't read carefully. I repeat:" << std::endl;
    } while (true);

    if (matches[2].length()) {
        return false;
    }

    return true;
}

void do_clear(db::EnvConfig& config, bool dry, bool always_yes, const std::vector<std::string>& table_names,
              bool drop) {
    config.readonly = false;

    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{db::open_env(config)};
    auto txn{env.start_write()};

    for (const auto& tablename : table_names) {
        if (!db::has_map(txn, tablename.c_str())) {
            std::cout << "Table " << tablename << " not found" << std::endl;
            continue;
        }

        mdbx::map_handle table_map{txn.open_map(tablename)};
        size_t rcount{txn.get_map_stat(table_map).ms_entries};

        if (!rcount && !drop) {
            std::cout << " Table " << tablename << " is already empty. Skipping" << std::endl;
            continue;
        }

        std::cout << "\n"
                  << (drop ? "Dropping" : "Emptying") << " table " << tablename << " (" << rcount << " records) "
                  << std::flush;

        if (!always_yes) {
            if (!user_confirmation()) {
                std::cout << "  Skipped." << std::endl;
                continue;
            }
        }

        std::cout << (dry ? "Simulating commit ..." : "Committing ...") << std::endl;

        if (drop) {
            txn.drop_map(table_map);
        } else {
            txn.clear_map(table_map);
        }
        if (dry) {
            txn.abort();
        } else {
            txn.commit();
        }
        txn = env.start_write();
    }
}

DbFreeInfo get_free_info(::mdbx::txn& txn) {
    DbFreeInfo ret{};

    ::mdbx::map_handle free_map{0};
    auto page_size{txn.get_map_stat(free_map).ms_psize};

    const auto& collect_func{[&ret, &page_size](ByteView key, ByteView value) {
        size_t txId;
        std::memcpy(&txId, key.data(), sizeof(size_t));
        uint32_t pagesCount;
        std::memcpy(&pagesCount, value.data(), sizeof(uint32_t));
        size_t pagesSize = pagesCount * page_size;
        ret.pages += pagesCount;
        ret.size += pagesSize;
        ret.entries.push_back({txId, pagesCount, pagesSize});
    }};

    auto free_crs{txn.open_cursor(free_map)};
    cursor_for_each(free_crs, collect_func);

    return ret;
}

DbInfo get_tables_info(::mdbx::txn& txn) {
    DbInfo ret{};
    DbTableInfo* table;

    ret.file_size = txn.env().get_info().mi_geo.current;

    // Get info from the free database
    ::mdbx::map_handle free_map{0};
    auto stat = txn.get_map_stat(free_map);
    auto info = txn.get_handle_info(free_map);
    table = new DbTableInfo{free_map.dbi, "FREE_DBI", stat, info};
    ret.page_size += table->stat.ms_psize;
    ret.pages += table->pages();
    ret.size += table->size();
    ret.tables.push_back(*table);

    // Get info from the unnamed database
    ::mdbx::map_handle main_map{1};
    stat = txn.get_map_stat(main_map);
    info = txn.get_handle_info(main_map);
    table = new DbTableInfo{main_map.dbi, "MAIN_DBI", stat, info};
    ret.page_size += table->stat.ms_psize;
    ret.pages += table->pages();
    ret.size += table->size();
    ret.tables.push_back(*table);

    const auto& collect_func{[&ret, &txn](ByteView key, ByteView) {
        const auto name{std::string(byte_view_to_string_view(key))};
        const auto map{txn.open_map(name)};
        const auto stat2{txn.get_map_stat(map)};
        const auto info2{txn.get_handle_info(map)};
        const auto* table2 = new DbTableInfo{map.dbi, std::string{name}, stat2, info2};

        ret.page_size += table2->stat.ms_psize;
        ret.pages += table2->pages();
        ret.size += table2->size();
        ret.tables.push_back(*table2);
    }};

    // Get all tables from the unnamed database
    auto main_crs{txn.open_cursor(main_map)};
    cursor_for_each(main_crs, collect_func);
    return ret;
}

void do_scan(db::EnvConfig& config) {
    static std::string fmt_hdr{" %3s %-24s %=50s %13s %13s %13s"};

    auto env{silkworm::db::open_env(config)};
    auto txn{env.start_read()};

    auto tablesInfo{get_tables_info(txn)};

    std::cout << "\n Database tables    : " << tablesInfo.tables.size() << "\n"
              << std::endl;

    if (!tablesInfo.tables.empty()) {
        std::cout << (boost::format(fmt_hdr) % "Dbi" % "Table name" % "Progress" % "Keys" % "Data" % "Total")
                  << std::endl;
        std::cout << (boost::format(fmt_hdr) % std::string(3, '-') % std::string(24, '-') % std::string(50, '-') %
                      std::string(13, '-') % std::string(13, '-') % std::string(13, '-'))
                  << std::flush;

        for (DbTableInfo item : tablesInfo.tables) {
            mdbx::map_handle tbl_map;

            std::cout << "\n"
                      << (boost::format(" %3u %-24s ") % item.id % item.name) << std::flush;

            if (item.id < 2) {
                tbl_map = mdbx::map_handle(item.id);
            } else {
                tbl_map = txn.open_map(item.name);
            }

            size_t key_size{0};
            size_t data_size{0};
            Progress progress{50};
            progress.set_task_count(item.stat.ms_entries);
            size_t batch_size{progress.get_increment_count()};

            auto tbl_crs{txn.open_cursor(tbl_map)};
            auto result = tbl_crs.to_first(/*throw_notfound =*/false);

            while (result) {
                key_size += result.key.size();
                data_size += result.value.size();
                if (!--batch_size) {
                    if (SignalHandler::signalled()) {
                        break;
                    }
                    progress.set_current(progress.get_current() + progress.get_increment_count());
                    std::cout << progress.print_interval('.') << std::flush;
                    batch_size = progress.get_increment_count();
                }
                result = tbl_crs.to_next(/*throw_notfound =*/false);
            }

            if (!SignalHandler::signalled()) {
                progress.set_current(item.stat.ms_entries);
                std::cout << progress.print_interval('.') << std::flush;
                std::cout << (boost::format(" %13s %13s %13s") % human_size(key_size) % human_size(data_size) %
                              human_size(key_size + data_size))
                          << std::flush;
            } else {
                break;
            }
        }
    }

    std::cout << "\n"
              << (SignalHandler::signalled() ? "Aborted" : "Done") << " !\n " << std::endl;
    txn.commit();
    env.close(config.shared);
}

void do_stages(db::EnvConfig& config) {
    static std::string fmt_hdr{" %-24s %10s "};
    static std::string fmt_row{" %-24s %10u %-8s"};

    auto env{silkworm::db::open_env(config)};
    auto txn{env.start_read()};
    if (!db::has_map(txn, db::table::kSyncStageProgress.name)) {
        throw std::runtime_error("Either not a Silkworm db or table " +
                                 std::string{db::table::kSyncStageProgress.name} + " not found");
    }

    auto crs{db::open_cursor(txn, db::table::kSyncStageProgress)};

    if (txn.get_map_stat(crs.map()).ms_entries) {
        std::cout << "\n"
                  << (boost::format(fmt_hdr) % "Stage Name" % "Block") << std::endl;
        std::cout << (boost::format(fmt_hdr) % std::string(24, '-') % std::string(10, '-')) << std::endl;

        auto result{crs.to_first(/*throw_notfound =*/false)};
        while (result) {
            size_t height{endian::load_big_u64(static_cast<uint8_t*>(result.value.data()))};

            // Handle "prune_" stages
            size_t offset{0};
            static const char* prune_prefix = "prune_";
            if (std::memcmp(result.key.data(), prune_prefix, 6) == 0) {
                offset = 6;
            }

            bool Known{db::stages::is_known_stage(result.key.char_ptr() + offset)};
            std::cout << (boost::format(fmt_row) % result.key.as_string() % height %
                          (Known ? std::string(8, ' ') : "Unknown"))
                      << std::endl;
            result = crs.to_next(/*throw_notfound =*/false);
        }
        std::cout << "\n"
                  << std::endl;
    } else {
        std::cout << "\n There are no stages to list\n"
                  << std::endl;
    }

    txn.commit();
    env.close(config.shared);
}

void do_migrations(db::EnvConfig& config) {
    static std::string fmt_hdr{" %-24s"};
    static std::string fmt_row{" %-24s"};

    auto env{silkworm::db::open_env(config)};
    auto txn{env.start_read()};

    if (!db::has_map(txn, db::table::kMigrations.name)) {
        throw std::runtime_error("Either not a Silkworm db or table " + std::string{db::table::kMigrations.name} +
                                 " not found");
    }

    auto crs{db::open_cursor(txn, db::table::kMigrations)};

    if (txn.get_map_stat(crs.map()).ms_entries) {
        std::cout << "\n"
                  << (boost::format(fmt_hdr) % "Migration Name") << std::endl;
        std::cout << (boost::format(fmt_hdr) % std::string(24, '-')) << std::endl;

        auto result{crs.to_first(/*throw_notfound =*/false)};
        while (result) {
            std::cout << (boost::format(fmt_row) % result.key.as_string()) << std::endl;
            result = crs.to_next(/*throw_notfound =*/false);
        }
        std::cout << "\n"
                  << std::endl;
    } else {
        std::cout << "\n There are no migrations to list\n"
                  << std::endl;
    }

    txn.commit();
    env.close(config.shared);
}

void do_stage_set(db::EnvConfig& config, std::string&& stage_name, uint32_t new_height, bool dry) {
    config.readonly = false;

    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{silkworm::db::open_env(config)};
    db::RWTxnManaged txn{env};
    if (!db::stages::is_known_stage(stage_name.c_str())) {
        throw std::runtime_error("Stage name " + stage_name + " is not known");
    }
    if (!db::has_map(txn, silkworm::db::table::kSyncStageProgress.name)) {
        throw std::runtime_error("Either non Silkworm db or table " +
                                 std::string(silkworm::db::table::kSyncStageProgress.name) + " not found");
    }
    auto old_height{db::stages::read_stage_progress(txn, stage_name.c_str())};
    db::stages::write_stage_progress(txn, stage_name.c_str(), new_height);
    if (!dry) {
        txn.commit_and_renew();
    }

    std::cout << "\n Stage " << stage_name << " touched from " << old_height << " to " << new_height << "\n"
              << std::endl;
}

void unwind(db::EnvConfig& config, BlockNum unwind_point, bool remove_blocks) {
    ensure(config.exclusive, "Function requires exclusive access to database");

    config.readonly = false;

    auto env{silkworm::db::open_env(config)};
    db::RWTxnManaged txn{env};
    auto chain_config{db::read_chain_config(txn)};
    ensure(chain_config.has_value(), "Not an initialized Silkworm db or unknown/custom chain");

    NodeSettings settings{
        .data_directory = std::make_unique<DataDirectory>(),
        .chaindata_env_config = config,
        .chain_config = chain_config};

    stagedsync::ExecutionPipeline stage_pipeline{&settings};
    const auto unwind_result{stage_pipeline.unwind(txn, unwind_point)};

    ensure(unwind_result == stagedsync::Stage::Result::kSuccess,
           "unwind failed: " + std::string{magic_enum::enum_name<stagedsync::Stage::Result>(unwind_result)});

    std::cout << "\n Staged pipeline unwind up to block: " << unwind_point << " completed\n";

    // In consensus-separated Sync/Execution design block headers and bodies are stored by the Sync component
    // not by the Execution component: hence, ExecutionPipeline will not remove them during unwind phase
    if (remove_blocks) {
        std::cout << " Removing also block headers and bodies up to block: " << unwind_point << "\n";

        // Remove the block bodies up to the unwind point
        const auto body_cursor{txn.rw_cursor(db::table::kBlockBodies)};
        const auto start_key{db::block_key(unwind_point)};
        std::size_t erased_bodies{0};
        auto body_data{body_cursor->lower_bound(db::to_slice(start_key), /*throw_notfound=*/false)};
        while (body_data) {
            body_cursor->erase();
            ++erased_bodies;
            body_data = body_cursor->to_next(/*throw_notfound=*/false);
        }
        std::cout << " Removed block bodies erased: " << erased_bodies << "\n";

        // Remove the block headers up to the unwind point
        const auto header_cursor{txn.rw_cursor(db::table::kHeaders)};
        std::size_t erased_headers{0};
        auto header_data{header_cursor->lower_bound(db::to_slice(start_key), /*throw_notfound=*/false)};
        while (header_data) {
            header_cursor->erase();
            ++erased_headers;
            header_data = header_cursor->to_next(/*throw_notfound=*/false);
        }
        std::cout << " Removed block headers erased: " << erased_headers << "\n";

        // Remove the canonical hashes up to the unwind point
        const auto canonical_cursor{txn.rw_cursor(db::table::kCanonicalHashes)};
        std::size_t erased_hashes{0};
        auto hash_data{canonical_cursor->lower_bound(db::to_slice(start_key), /*throw_notfound=*/false)};
        while (hash_data) {
            canonical_cursor->erase();
            ++erased_hashes;
            hash_data = canonical_cursor->to_next(/*throw_notfound=*/false);
        }
        std::cout << " Removed canonical hashes erased: " << erased_hashes << "\n";

        txn.commit_and_stop();
    }
}

void do_tables(db::EnvConfig& config) {
    static std::string fmt_hdr{" %3s %-26s %10s %2s %10s %10s %10s %12s %10s %10s"};
    static std::string fmt_row{" %3i %-26s %10u %2u %10u %10u %10u %12s %10s %10s"};

    auto env{silkworm::db::open_env(config)};
    auto txn{env.start_read()};

    auto dbTablesInfo{get_tables_info(txn)};
    auto dbFreeInfo{get_free_info(txn)};

    std::cout << "\n Database tables          : " << dbTablesInfo.tables.size() << std::endl;
    std::cout << " Effective pruning        : " << db::read_prune_mode(txn).to_string() << "\n"
              << std::endl;

    if (!dbTablesInfo.tables.empty()) {
        std::cout << (boost::format(fmt_hdr) % "Dbi" % "Table name" % "Records" % "D" % "Branch" % "Leaf" % "Overflow" %
                      "Size" % "Key" % "Value")
                  << std::endl;
        std::cout << (boost::format(fmt_hdr) % std::string(3, '-') % std::string(26, '-') % std::string(10, '-') %
                      std::string(2, '-') % std::string(10, '-') % std::string(10, '-') % std::string(10, '-') %
                      std::string(12, '-') % std::string(10, '-') % std::string(10, '-'))
                  << std::endl;

        for (auto& item : dbTablesInfo.tables) {
            auto keyMode = magic_enum::enum_name(item.info.key_mode());
            auto valueMode = magic_enum::enum_name(item.info.value_mode());
            std::cout << (boost::format(fmt_row) % item.id % item.name % item.stat.ms_entries % item.stat.ms_depth %
                          item.stat.ms_branch_pages % item.stat.ms_leaf_pages % item.stat.ms_overflow_pages %
                          human_size(item.size()) % keyMode % valueMode)
                      << std::endl;
        }
    }

    std::cout << "\n"
              << " Database file size   (A) : " << (boost::format("%13s") % human_size(dbTablesInfo.file_size)) << "\n"
              << " Data pages count         : " << (boost::format("%13u") % dbTablesInfo.pages) << "\n"
              << " Data pages size      (B) : " << (boost::format("%13s") % human_size(dbTablesInfo.size)) << "\n"
              << " Free pages count         : " << (boost::format("%13u") % dbFreeInfo.pages) << "\n"
              << " Free pages size      (C) : " << (boost::format("%13s") % human_size(dbFreeInfo.size)) << "\n"
              << " Reclaimable space        : "
              << (boost::format("%13s") % human_size(dbTablesInfo.file_size - dbTablesInfo.size + dbFreeInfo.size))
              << " == A - B + C \n"
              << std::endl;

    txn.commit();
    env.close(config.shared);
}

void do_freelist(db::EnvConfig& config, bool detail) {
    static std::string fmt_hdr{"%9s %9s %12s"};
    static std::string fmt_row{"%9u %9u %12s"};

    auto env{silkworm::db::open_env(config)};
    auto txn{env.start_read()};

    auto db_free_info{get_free_info(txn)};
    if (!db_free_info.entries.empty() && detail) {
        std::cout << "\n"
                  << (boost::format(fmt_hdr) % "TxId" % "Pages" % "Size") << "\n"
                  << (boost::format(fmt_hdr) % std::string(9, '-') % std::string(9, '-') % std::string(12, '-'))
                  << std::endl;
        for (auto& item : db_free_info.entries) {
            std::cout << (boost::format(fmt_row) % item.id % item.pages % human_size(item.size)) << std::endl;
        }
    }
    std::cout << "\n Record count         : " << boost::format("%13u") % db_free_info.entries.size() << "\n"
              << " Free pages count     : " << boost::format("%13u") % db_free_info.pages << "\n"
              << " Free pages size      : " << boost::format("%13s") % human_size(db_free_info.size) << "\n"
              << std::endl;

    txn.commit();
    env.close(config.shared);
}

void do_schema(db::EnvConfig& config) {
    auto env{silkworm::db::open_env(config)};
    db::ROTxnManaged txn{env};

    auto schema_version{db::read_schema_version(txn)};
    if (!schema_version.has_value()) {
        throw std::runtime_error("Not a Silkworm db or no schema version found");
    }
    std::cout << "\n"
              << "Database schema version : " << schema_version->to_string() << "\n"
              << std::endl;

    env.close(config.shared);
}

void do_compact(db::EnvConfig& config, const std::string& work_dir, bool replace, bool nobak) {
    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    fs::path work_path{work_dir};
    if (work_path.has_filename()) {
        work_path += fs::path::preferred_separator;
    }
    std::error_code ec;
    fs::create_directories(work_path, ec);
    if (ec) {
        throw std::runtime_error("Directory " + work_path.string() + " does not exist and could not be created");
    }

    fs::path target_file_path{work_path / fs::path(db::kDbDataFileName)};
    if (fs::exists(target_file_path)) {
        throw std::runtime_error("Directory " + work_path.string() + " already contains an " +
                                 std::string(db::kDbDataFileName) + " file");
    }

    auto env{silkworm::db::open_env(config)};

    // Determine file size of origin db
    size_t src_filesize{env.get_info().mi_geo.current};

    // Ensure target working directory has enough free space
    // at least the size of origin db
    auto target_space = fs::space(target_file_path.parent_path());
    if (target_space.free <= src_filesize) {
        throw std::runtime_error("Insufficient disk space on working directory's partition");
    }

    std::cout << "\n Compacting database from " << config.path << "\n into " << target_file_path
              << "\n Please be patient as there is no progress report ..." << std::endl;
    env.copy(/*destination*/ target_file_path.string(), /*compactify*/ true, /*forcedynamic*/ true);
    std::cout << "\n Database compaction " << (SignalHandler::signalled() ? "aborted !" : "completed ...") << std::endl;
    env.close();

    if (!SignalHandler::signalled()) {
        // Do we have a valid compacted file on disk ?
        // replace source with target
        if (!fs::exists(target_file_path)) {
            throw std::runtime_error("Can't locate compacted database");
        }

        // Do we have to replace original file ?
        if (replace) {
            auto source_file_path{db::get_datafile_path(fs::path(config.path))};
            // Create a backup copy before replacing ?
            if (!nobak) {
                std::cout << " Creating backup copy of origin database ..." << std::endl;
                std::string src_file_back{db::kDbDataFileName};
                src_file_back.append(".bak");
                fs::path src_path_bak{source_file_path.parent_path() / fs::path{src_file_back}};
                if (fs::exists(src_path_bak)) {
                    fs::remove(src_path_bak);
                }
                fs::rename(source_file_path, src_path_bak);
            }

            std::cout << " Replacing origin database with compacted ..." << std::endl;
            if (fs::exists(source_file_path)) {
                fs::remove(source_file_path);
            }
            fs::rename(target_file_path, source_file_path);
        }
    }
}

void do_copy(db::EnvConfig& src_config, const std::string& target_dir, bool create, bool noempty,
             std::vector<std::string>& names, std::vector<std::string>& xnames) {
    if (!src_config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to source database");
    }

    fs::path target_path{target_dir};
    if (target_path.has_filename()) {
        target_path += fs::path::preferred_separator;
    }
    if (!fs::exists(target_path) || !fs::is_directory(target_path)) {
        if (!create) {
            throw std::runtime_error("Directory " + target_path.string() + " does not exist. Try --create");
        }
        std::error_code ec;
        fs::create_directories(target_path, ec);
        if (ec) {
            throw std::runtime_error("Directory " + target_path.string() + " does not exist and could not be created");
        }
    }

    // Target config
    db::EnvConfig tgt_config{target_path.string()};
    tgt_config.exclusive = true;
    fs::path target_file_path{target_path / fs::path(db::kDbDataFileName)};
    if (!fs::exists(target_file_path)) {
        tgt_config.create = true;
    }

    // Source db
    auto src_env{silkworm::db::open_env(src_config)};
    auto src_txn{src_env.start_read()};

    // Target db
    auto tgt_env{silkworm::db::open_env(tgt_config)};
    auto tgt_txn{tgt_env.start_write()};

    // Get free info and tables from both source and target environment
    auto source_db_info = get_tables_info(src_txn);
    auto target_db_info = get_tables_info(tgt_txn);

    // Check source db has tables to copy besides the two system tables
    if (source_db_info.tables.size() < 3) {
        throw std::runtime_error("Source db has no tables to copy.");
    }

    size_t bytesWritten{0};
    std::cout << boost::format(" %-24s %=50s") % "Table" % "Progress" << std::endl;
    std::cout << boost::format(" %-24s %=50s") % std::string(24, '-') % std::string(50, '-') << std::flush;

    // Loop source tables
    for (auto& src_table : source_db_info.tables) {
        if (SignalHandler::signalled()) {
            break;
        }
        std::cout << "\n " << boost::format("%-24s ") % src_table.name << std::flush;

        // Is this a system table ?
        if (src_table.id < 2) {
            std::cout << "Skipped (SYSTEM TABLE)" << std::flush;
            continue;
        }

        // Is this table present in the list user has provided ?
        if (!names.empty()) {
            auto it = std::ranges::find(names, src_table.name);
            if (it == names.end()) {
                std::cout << "Skipped (no match --tables)" << std::flush;
                continue;
            }
        }

        // Is this table present in the list user has excluded ?
        if (!xnames.empty()) {
            auto it = std::ranges::find(xnames, src_table.name);
            if (it != xnames.end()) {
                std::cout << "Skipped (match --xtables)" << std::flush;
                continue;
            }
        }

        // Is table empty ?
        if (!src_table.stat.ms_entries && noempty) {
            std::cout << "Skipped (--noempty)" << std::flush;
            continue;
        }

        // Is source table already present in target db ?
        bool exists_on_target{false};
        bool populated_on_target{false};
        if (!target_db_info.tables.empty()) {
            auto it = std::ranges::find_if(
                target_db_info.tables, [&src_table](DbTableInfo& item) -> bool { return item.name == src_table.name; });
            if (it != target_db_info.tables.end()) {
                exists_on_target = true;
                populated_on_target = (it->stat.ms_entries > 0);
            }
        }

        // Ready to copy
        auto src_table_map{src_txn.open_map(src_table.name)};
        auto src_table_info{src_txn.get_handle_info(src_table_map)};

        // If table does not exist on target create it with same flags as
        // origin table. Check the info match otherwise.
        mdbx::map_handle tgt_table_map;
        if (!exists_on_target) {
            tgt_table_map = tgt_txn.create_map(src_table.name, src_table_info.key_mode(), src_table_info.value_mode());
        } else {
            tgt_table_map = tgt_txn.open_map(src_table.name);
            auto tgt_table_info{tgt_txn.get_handle_info(tgt_table_map)};
            if (src_table_info.flags != tgt_table_info.flags) {
                std::cout << "Skipped (source and target have incompatible flags)" << std::flush;
                continue;
            }
        }

        // Loop source and write into target
        Progress progress{50};
        progress.set_task_count(src_table.stat.ms_entries);
        size_t batch_size{progress.get_increment_count()};
        bool batch_committed{false};

        auto src_table_crs{src_txn.open_cursor(src_table_map)};
        auto tgt_table_crs{tgt_txn.open_cursor(tgt_table_map)};
        MDBX_put_flags_t put_flags{populated_on_target
                                       ? MDBX_put_flags_t::MDBX_UPSERT
                                       : ((src_table_info.flags & MDBX_DUPSORT) ? MDBX_put_flags_t::MDBX_APPENDDUP
                                                                                : MDBX_put_flags_t::MDBX_APPEND)};

        auto data{src_table_crs.to_first(/*throw_notfound =*/false)};
        while (data) {
            ::mdbx::error::success_or_throw(tgt_table_crs.put(data.key, &data.value, put_flags));
            bytesWritten += (data.key.length() + data.value.length());
            if (bytesWritten >= 2_Gibi) {
                tgt_txn.commit();
                tgt_txn = tgt_env.start_write();
                tgt_table_crs.renew(tgt_txn);
                batch_committed = true;
                bytesWritten = 0;
            }

            if (!--batch_size) {
                if (SignalHandler::signalled()) {
                    break;
                }
                progress.set_current(progress.get_current() + progress.get_increment_count());
                std::cout << progress.print_interval(batch_committed ? 'W' : '.') << std::flush;
                batch_committed = false;
                batch_size = progress.get_increment_count();
            }

            data = src_table_crs.to_next(/*throw_notfound =*/false);
        }

        // Close all
        if (SignalHandler::signalled()) {
            break;
        }

        tgt_txn.commit();
        tgt_txn = tgt_env.start_write();
        batch_committed = true;
        bytesWritten = 0;

        progress.set_current(src_table.stat.ms_entries);
        std::cout << progress.print_interval(batch_committed ? 'W' : '.') << std::flush;
    }

    std::cout << "\n All done!" << std::endl;
}

static size_t print_multi_table_diff(db::ROCursorDupSort* cursor1, db::ROCursorDupSort* cursor2, bool force_print = false) {
    size_t diff_count{0};
    auto result1{cursor1->to_first()};
    auto result2{cursor2->to_first()};
    while (result1.done && result2.done) {
        const auto key1{result1.key};
        const auto key2{result2.key};
        if (key1 != key2 || force_print) {
            std::cout << "k1=" << silkworm::to_hex({static_cast<const uint8_t*>(key1.data()), key1.size()})
                      << " k2=" << silkworm::to_hex({static_cast<const uint8_t*>(key2.data()), key2.size()}) << "\n";
            ++diff_count;
        }
        bool first{true};
        while (result1.done && result2.done) {
            const auto& value1{result1.value};
            const auto& value2{result2.value};
            if (value1 != value2 || force_print) {
                if (first) {
                    if (key1 == key2 && !force_print) {
                        std::cout << "k1=k2=" << silkworm::to_hex({static_cast<const uint8_t*>(key1.data()), key1.size()}) << "\n";
                    }
                    first = false;
                }
                const auto v1_hex{silkworm::to_hex({static_cast<const uint8_t*>(value1.data()), value1.size()})};
                const auto v2_hex{silkworm::to_hex({static_cast<const uint8_t*>(value2.data()), value2.size()})};
                std::cout << "v1=" << v1_hex << " v2=" << v2_hex << "\n";
                ++diff_count;
                if (diff_count % 100 == 0) {
                    if (!user_confirmation("Do you need any more diffs?")) {
                        return diff_count;
                    }
                }
            }
            result1 = cursor1->to_current_next_multi(/*throw_notfound=*/false);
            result2 = cursor2->to_current_next_multi(/*throw_notfound=*/false);
        }
        while (result1.done) {
            if (first) {
                if (key1 == key2 && !force_print) {
                    std::cout << "k1=k2=" << silkworm::to_hex({static_cast<const uint8_t*>(key1.data()), key1.size()}) << "\n";
                }
                first = false;
            }
            const auto& value1{result1.value};
            const auto v1_hex{silkworm::to_hex({static_cast<const uint8_t*>(value1.data()), value1.size()})};
            std::cout << "v1=" << v1_hex << "\n";
            ++diff_count;
            if (diff_count % 100 == 0) {
                if (!user_confirmation("Do you need any more diffs?")) {
                    return diff_count;
                }
            }
            result1 = cursor1->to_current_next_multi(/*throw_notfound=*/false);
        }
        while (result2.done) {
            if (first) {
                if (key1 == key2 && !force_print) {
                    std::cout << "k1=k2=" << silkworm::to_hex({static_cast<const uint8_t*>(key1.data()), key1.size()}) << "\n";
                }
                first = false;
            }
            const auto& value2{result2.value};
            const auto v2_hex{silkworm::to_hex({static_cast<const uint8_t*>(value2.data()), value2.size()})};
            std::cout << " v2=" << v2_hex << "\n";
            ++diff_count;
            if (diff_count % 100 == 0) {
                if (!user_confirmation("Do you need any more diffs?")) {
                    return diff_count;
                }
            }
            result2 = cursor2->to_current_next_multi(/*throw_notfound=*/false);
        }
        result1 = cursor1->to_next(/*throw_notfound=*/false);
        result2 = cursor2->to_next(/*throw_notfound=*/false);
    }
    while (result1.done) {
        const auto key1{result1.key};
        std::cout << "k1=" << silkworm::to_hex({static_cast<const uint8_t*>(key1.data()), key1.size()}) << "\n";
        ++diff_count;
        if (diff_count % 100 == 0) {
            if (!user_confirmation("Do you need any more diffs?")) {
                return diff_count;
            }
        }
        result1 = cursor1->to_next(/*throw_notfound=*/false);
    }
    while (result2.done) {
        const auto key2{result2.key};
        std::cout << "k2=" << silkworm::to_hex({static_cast<const uint8_t*>(key2.data()), key2.size()}) << "\n";
        ++diff_count;
        if (diff_count % 100 == 0) {
            if (!user_confirmation("Do you need any more diffs?")) {
                return diff_count;
            }
        }
        result2 = cursor2->to_next(/*throw_notfound=*/false);
    }
    return diff_count;
}

static size_t print_single_table_diff(db::ROCursor* cursor1, db::ROCursor* cursor2, bool force_print) {
    size_t diff_count{0};
    auto result1{cursor1->to_first()};
    auto result2{cursor2->to_first()};
    while (result1.done && result2.done) {
        const auto key1{result1.key};
        const auto key2{result2.key};
        if (key1 != key2 || force_print) {
            std::cout << "k1=" << silkworm::to_hex({static_cast<const uint8_t*>(key1.data()), key1.size()})
                      << " k2=" << silkworm::to_hex({static_cast<const uint8_t*>(key2.data()), key2.size()}) << "\n";
            ++diff_count;
        }
        bool first{true};
        const auto& value1{result1.value};
        const auto& value2{result2.value};
        if (value1 != value2 || force_print) {
            if (first && !force_print) {
                if (key1 == key2) {
                    std::cout << "k1=k2=" << silkworm::to_hex({static_cast<const uint8_t*>(key1.data()), key1.size()}) << "\n";
                }
                first = false;
            }
            const auto v1_hex{silkworm::to_hex({static_cast<const uint8_t*>(value1.data()), value1.size()})};
            const auto v2_hex{silkworm::to_hex({static_cast<const uint8_t*>(value2.data()), value2.size()})};
            std::cout << "v1=" << v1_hex << " v2=" << v2_hex << "\n";
            ++diff_count;
            if (diff_count % 100 == 0) {
                if (!user_confirmation("Do you need any more diffs?")) {
                    return diff_count;
                }
            }
        }
        result1 = cursor1->to_next(/*throw_notfound=*/false);
        result2 = cursor2->to_next(/*throw_notfound=*/false);
    }
    while (result1.done) {
        const auto key1{result1.key};
        std::cout << "k1=" << silkworm::to_hex({static_cast<const uint8_t*>(key1.data()), key1.size()}) << "\n";
        ++diff_count;
        if (diff_count % 100 == 0) {
            if (!user_confirmation("Do you need any more diffs?")) {
                return diff_count;
            }
        }
        result1 = cursor1->to_next(/*throw_notfound=*/false);
    }
    while (result2.done) {
        const auto key2{result2.key};
        std::cout << "k2=" << silkworm::to_hex({static_cast<const uint8_t*>(key2.data()), key2.size()}) << "\n";
        ++diff_count;
        if (diff_count % 100 == 0) {
            if (!user_confirmation("Do you need any more diffs?")) {
                return diff_count;
            }
        }
        result2 = cursor2->to_next(/*throw_notfound=*/false);
    }
    return diff_count;
}

static void print_table_diff(db::ROTxn& txn1, db::ROTxn& txn2, const DbTableInfo& table1, const DbTableInfo& table2, bool force_print = false) {
    ensure(table1.name == table2.name, "name mismatch: " + table1.name + " vs " + table2.name);
    ensure(table1.info.key_mode() == table2.info.key_mode(),
           "key_mode mismatch: " + std::to_string(int(table1.info.key_mode())) + " vs " + std::to_string(int(table2.info.key_mode())));
    ensure(table1.info.value_mode() == table2.info.value_mode(),
           "value_mode mismatch: " + std::to_string(int(table1.info.value_mode())) + " vs " + std::to_string(int(table2.info.value_mode())));

    db::MapConfig table1_config{
        .name = table1.name.c_str(),
        .key_mode = table1.info.key_mode(),
        .value_mode = table1.info.value_mode(),
    };
    db::MapConfig table2_config{
        .name = table2.name.c_str(),
        .key_mode = table2.info.key_mode(),
        .value_mode = table2.info.value_mode(),
    };
    if (table1_config.value_mode == ::mdbx::value_mode::single) {
        const auto cursor1{txn1.ro_cursor(table1_config)};
        const auto cursor2{txn2.ro_cursor(table2_config)};
        const auto diff_count{print_single_table_diff(cursor1.get(), cursor2.get(), force_print)};
        if (diff_count == 0) {
            std::cout << "No diff found for single-value table " << table1_config.name << "\n";
        }
    } else if (table1_config.value_mode == ::mdbx::value_mode::multi) {
        const auto cursor1{txn1.ro_cursor_dup_sort(table1_config)};
        const auto cursor2{txn2.ro_cursor_dup_sort(table2_config)};
        const auto diff_count{print_multi_table_diff(cursor1.get(), cursor2.get(), force_print)};
        if (diff_count == 0) {
            std::cout << "No diff found for multi-value table " << table1_config.name << "\n";
        }
    } else {
        log::Warning() << "unsupported value mode: " << magic_enum::enum_name(table1_config.value_mode);
    }
}

static std::optional<DbTableInfo> find_table(const DbInfo& db_info, std::string_view table) {
    const auto& db_tables{db_info.tables};
    const auto it{std::find_if(db_tables.begin(), db_tables.end(), [=](const auto& t) { return t.name == table; })};
    return it != db_tables.end() ? std::make_optional<DbTableInfo>(*it) : std::nullopt;
}

static DbComparisonResult compare_db_schema(const DbInfo& db1_info, const DbInfo& db2_info) {
    const auto& db1_tables{db1_info.tables};
    const auto& db2_tables{db2_info.tables};

    // Check both databases have the same number of tables
    if (db1_tables.size() != db2_tables.size()) {
        return tl::make_unexpected("mismatch in number of tables: db1 has " + std::to_string(db1_tables.size()) +
                                   ", db2 has" + std::to_string(db2_tables.size()));
    }

    // Check both databases have the same table names
    for (auto& db1_table : db1_tables) {
        if (std::find(db2_tables.begin(), db2_tables.end(), db1_table) == db2_tables.end()) {
            return tl::make_unexpected("db1 table " + db1_table.name + " not present in db2\n");
        }
    }
    for (auto& db2_table : db2_tables) {
        if (std::find(db1_tables.begin(), db1_tables.end(), db2_table) == db1_tables.end()) {
            return tl::make_unexpected("db2 table " + db2_table.name + " not present in db1\n");
        }
    }

    return {};
}

static DbComparisonResult compare_table_content(db::ROTxn& txn1, db::ROTxn& txn2, const DbTableInfo& db1_table, const DbTableInfo& db2_table,
                                                bool check_pages, bool verbose) {
    // Check both databases have the same stats (e.g. number of records) for the specified table
    if (const auto result{compare(db1_table, db2_table, check_pages)}; !result) {
        const std::string error_message{"mismatch in table " + db1_table.name + ": " + result.error()};
        if (verbose) {
            std::cerr << error_message << "\n";
            print_table_diff(txn1, txn2, db1_table, db2_table);
        }
        return tl::make_unexpected(error_message);
    }

    return {};
}

static DbComparisonResult compare_db_content(db::ROTxn& txn1, db::ROTxn& txn2, const DbInfo& db1_info, const DbInfo& db2_info,
                                             bool check_pages, bool verbose) {
    const auto& db1_tables{db1_info.tables};
    const auto& db2_tables{db2_info.tables};
    SILKWORM_ASSERT(db1_tables.size() == db2_tables.size());

    // Check both databases have the same content for each table
    for (size_t i{0}; i < db1_tables.size(); ++i) {
        if (const auto result{compare_table_content(txn1, txn2, db1_tables[i], db2_tables[i], check_pages, verbose)}; !result) {
            return result;
        }
    }

    return {};
}

void compare(db::EnvConfig& config, const fs::path& target_datadir_path, bool check_pages, bool verbose, std::optional<std::string_view> table) {
    ensure(fs::exists(target_datadir_path), "target datadir " + target_datadir_path.string() + " does not exist");
    ensure(fs::is_directory(target_datadir_path), "target datadir " + target_datadir_path.string() + " must be a folder");

    DataDirectory target_datadir{target_datadir_path};
    db::EnvConfig target_config{target_datadir.chaindata().path()};

    auto source_env{db::open_env(config)};
    db::ROTxnManaged source_txn{source_env};
    const auto source_db_info{get_tables_info(source_txn)};

    auto target_env{db::open_env(target_config)};
    db::ROTxnManaged target_txn{target_env};
    const auto target_db_info{get_tables_info(target_txn)};

    if (table) {
        // Check both databases have the specified table
        const auto db1_table{find_table(source_db_info, *table)};
        if (!db1_table) {
            throw std::runtime_error{"cannot find table " + std::string(*table) + " in db1"};
        }
        const auto db2_table{find_table(target_db_info, *table)};
        if (!db2_table) {
            throw std::runtime_error{"cannot find table " + std::string(*table) + " in db2"};
        }

        // Check both databases have the same content in the specified table
        if (const auto result{compare_table_content(source_txn, target_txn, *db1_table, *db2_table, check_pages, verbose)}; !result) {
            throw std::runtime_error{result.error()};
        }
    } else {
        // Check both databases have the same tables
        if (const auto result{compare_db_schema(source_db_info, target_db_info)}; !result) {
            throw std::runtime_error{result.error()};
        }

        // Check both databases have the same content in each table
        if (const auto result{compare_db_content(source_txn, target_txn, source_db_info, target_db_info, check_pages, verbose)}; !result) {
            throw std::runtime_error{result.error()};
        }
    }
}

/**
 * \brief Initializes a silkworm db.
 *
 * Can parse a custom genesis file in json format or import data from known chain configs
 *
 * \param DataDir data_dir : hold data directory info about db paths
 * \param json_file : a string representing the path where to load custom json from
 * \param uint32_t chain_id : an identifier for a known chain
 * \param bool dry : whether or not commit data or run in simulation
 *
 */
void do_init_genesis(DataDirectory& data_dir, const std::string&& json_file, uint32_t chain_id, bool dry) {
    // Check datadir does not exist
    if (data_dir.exists()) {
        throw std::runtime_error("Provided data directory already exist");
    }

    // Ensure data directory tree is built
    data_dir.deploy();

    // Retrieve source data either from provided json file
    // or from embedded sources
    std::string source_data;
    if (!json_file.empty()) {
        std::ifstream ifs(json_file);
        source_data = std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    } else if (chain_id != 0) {
        source_data = read_genesis_data(chain_id);
    } else {
        throw std::invalid_argument("Either json file or chain_id must be provided");
    }

    // Parse Json data
    // N.B. = instead of {} initialization due to https://github.com/nlohmann/json/issues/2204
    auto genesis_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);

    // Prime database
    db::EnvConfig config{data_dir.chaindata().path().string(), /*create*/ true};
    auto env{db::open_env(config)};
    db::RWTxnManaged txn{env};
    db::table::check_or_create_chaindata_tables(txn);
    db::initialize_genesis(txn, genesis_json, /*allow_exceptions=*/true);

    // Set schema version
    silkworm::db::VersionBase v{3, 0, 0};
    db::write_schema_version(txn, v);

    if (!dry) {
        txn.commit_and_renew();
    } else {
        txn.abort();
    }
    env.close();
}

void do_chainconfig(db::EnvConfig& config) {
    auto env{silkworm::db::open_env(config)};
    db::ROTxnManaged txn{env};
    auto chain_config{db::read_chain_config(txn)};
    if (!chain_config.has_value()) {
        throw std::runtime_error("Not an initialized Silkworm db or unknown/custom chain ");
    }
    const auto& chain{chain_config.value()};
    std::cout << "\n Chain ID: " << chain.chain_id
              << "\n Settings (json): \n"
              << chain.to_json().dump(/*indent=*/2) << "\n\n";
}

void print_canonical_blocks(db::EnvConfig& config, BlockNum from, std::optional<BlockNum> to, uint64_t step) {
    auto env{silkworm::db::open_env(config)};
    db::ROTxnManaged txn{env};

    // Determine last canonical block number
    auto canonical_hashes_table{txn.ro_cursor(db::table::kCanonicalHashes)};
    auto last_data{canonical_hashes_table->to_last(/*throw_notfound=*/false)};
    ensure(last_data.done, "Table CanonicalHashes is empty");
    ensure(last_data.key.size() == sizeof(BlockNum), "Table CanonicalHashes has unexpected key size");

    // Use last block as max block if to is missing and perform range checks
    BlockNum last{db::block_number_from_key(last_data.key)};
    if (to) {
        ensure(from <= *to, "Block from=" + std::to_string(from) + " must not be greater than to=" + std::to_string(*to));
        ensure(*to <= last, "Block to=" + std::to_string(*to) + " must not be greater than last=" + std::to_string(last));
    } else {
        ensure(from <= last, "Block from=" + std::to_string(from) + " must not be greater than last=" + std::to_string(last));
        to = last;
    }

    // Read the range of block headers and bodies from database
    auto block_headers_table{txn.ro_cursor(db::table::kHeaders)};
    auto block_bodies_table{txn.ro_cursor(db::table::kBlockBodies)};
    for (BlockNum block_number{from}; block_number <= *to; block_number += step) {
        // Lookup each canonical block hash from each block number
        auto block_number_key{db::block_key(block_number)};
        auto ch_data{canonical_hashes_table->find(db::to_slice(block_number_key), /*throw_notfound=*/false)};
        ensure(ch_data.done, "Table CanonicalHashes does not contain key=" + to_hex(block_number_key));
        const auto block_hash{to_bytes32(db::from_slice(ch_data.value))};

        // Read and decode each canonical block header
        auto block_key{db::block_key(block_number, block_hash.bytes)};
        auto bh_data{block_headers_table->find(db::to_slice(block_key), /*throw_notfound=*/false)};
        ensure(bh_data.done, "Table Headers does not contain key=" + to_hex(block_key));
        ByteView block_header_data{db::from_slice(bh_data.value)};
        BlockHeader header;
        const auto res{rlp::decode(block_header_data, header)};
        ensure(res.has_value(), "Cannot decode block header from rlp=" + to_hex(db::from_slice(bh_data.value)));

        // Read and decode each canonical block body
        auto bb_data{block_bodies_table->find(db::to_slice(block_key), /*throw_notfound=*/false)};
        if (!bb_data.done) {
            break;
        }
        ByteView block_body_data{db::from_slice(bb_data.value)};
        const auto stored_body{db::detail::decode_stored_block_body(block_body_data)};

        // Print block information to console
        std::cout << "\nBlock number=" << block_number << "\n\n";
        print_header(header);
        std::cout << "\n";
        print_body(stored_body);
        std::cout << "\n\n";
    }
}

void print_blocks(db::EnvConfig& config, BlockNum from, std::optional<BlockNum> to, uint64_t step) {
    auto env{silkworm::db::open_env(config)};
    db::ROTxnManaged txn{env};

    // Determine last block header number
    auto block_headers_table{txn.ro_cursor(db::table::kHeaders)};
    auto last_data{block_headers_table->to_last(/*throw_notfound=*/false)};
    ensure(last_data.done, "Table Headers is empty");
    ensure(last_data.key.size() == sizeof(BlockNum) + kHashLength, "Table Headers has unexpected key size");

    // Use last block as max block if to is missing and perform range checks
    BlockNum last{db::block_number_from_key(last_data.key)};
    if (to) {
        ensure(from <= *to, "Block from=" + std::to_string(from) + " must not be greater than to=" + std::to_string(*to));
        ensure(*to <= last, "Block to=" + std::to_string(*to) + " must not be greater than last=" + std::to_string(last));
    } else {
        ensure(from <= last, "Block from=" + std::to_string(from) + " must not be greater than last=" + std::to_string(last));
        to = last;
    }

    // Read the range of block headers and bodies from database
    auto block_bodies_table{txn.ro_cursor(db::table::kBlockBodies)};
    for (BlockNum block_number{from}; block_number <= *to; block_number += step) {
        // Read and decode each block header
        auto block_key{db::block_key(block_number)};
        auto bh_data{block_headers_table->lower_bound(db::to_slice(block_key), /*throw_notfound=*/false)};
        ensure(bh_data.done, "Table Headers does not contain key=" + to_hex(block_key));
        ByteView block_header_data{db::from_slice(bh_data.value)};
        BlockHeader header;
        const auto res{rlp::decode(block_header_data, header)};
        ensure(res.has_value(), "Cannot decode block header from rlp=" + to_hex(db::from_slice(bh_data.value)));

        // Read and decode each block body
        auto bb_data{block_bodies_table->lower_bound(db::to_slice(block_key), /*throw_notfound=*/false)};
        if (!bb_data.done) {
            break;
        }
        ByteView block_body_data{db::from_slice(bb_data.value)};
        const auto stored_body{db::detail::decode_stored_block_body(block_body_data)};

        // Print block information to console
        std::cout << "\nBlock number=" << block_number << "\n\n";
        print_header(header);
        std::cout << "\n";
        print_body(stored_body);
        std::cout << "\n\n";
    }
}

void do_first_byte_analysis(db::EnvConfig& config) {
    static std::string fmt_hdr{" %-24s %=50s "};

    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{silkworm::db::open_env(config)};
    db::ROTxnManaged txn{env};

    std::cout << "\n"
              << (boost::format(fmt_hdr) % "Table name" % "%") << "\n"
              << (boost::format(fmt_hdr) % std::string(24, '-') % std::string(50, '-')) << "\n"
              << (boost::format(" %-24s ") % db::table::kCode.name) << std::flush;

    std::unordered_map<uint8_t, size_t> histogram;
    auto code_cursor{db::open_cursor(txn, db::table::kCode)};

    Progress progress{50};
    size_t total_entries{txn->get_map_stat(code_cursor.map()).ms_entries};
    progress.set_task_count(total_entries);
    size_t batch_size{progress.get_increment_count()};

    code_cursor.to_first();
    cursor_for_each(code_cursor,
                    [&histogram, &batch_size, &progress](ByteView, ByteView value) {
                        if (value.length() > 0) {
                            uint8_t first_byte{value.at(0)};
                            ++histogram[first_byte];
                        }
                        if (!--batch_size) {
                            progress.set_current(progress.get_current() + progress.get_increment_count());
                            std::cout << progress.print_interval('.') << std::flush;
                            batch_size = progress.get_increment_count();
                        }
                    });

    BlockNum last_block{db::stages::read_stage_progress(txn, db::stages::kExecutionKey)};
    progress.set_current(total_entries);
    std::cout << progress.print_interval('.') << std::endl;

    std::cout << "\n Last block : " << last_block << "\n Contracts  : " << total_entries << "\n"
              << std::endl;

    // Sort histogram by usage (from most used to less used)
    std::vector<std::pair<uint8_t, size_t>> histogram_sorted;
    std::copy(histogram.begin(), histogram.end(),
              std::back_inserter<std::vector<std::pair<uint8_t, size_t>>>(histogram_sorted));
    std::sort(histogram_sorted.begin(), histogram_sorted.end(),
              [](std::pair<uint8_t, size_t>& a, std::pair<uint8_t, size_t>& b) -> bool {
                  return a.second == b.second ? a.first < b.first : a.second > b.second;
              });

    if (!histogram_sorted.empty()) {
        std::cout << (boost::format(" %-4s %8s") % "Byte" % "Count") << "\n"
                  << (boost::format(" %-4s %8s") % std::string(4, '-') % std::string(8, '-')) << std::endl;
        for (const auto& [byte_code, usage_count] : histogram_sorted) {
            std::cout << (boost::format(" 0x%02x %8u") % static_cast<int>(byte_code) % usage_count) << std::endl;
        }
    }

    std::cout << "\n"
              << std::endl;
}

void do_extract_headers(db::EnvConfig& config, const std::string& file_name, uint32_t step) {
    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{silkworm::db::open_env(config)};
    db::ROTxnManaged txn{env};

    // We can store all header hashes into a single byte array given all hashes have same length.
    // We only need to ensure that the total size of the byte array is a multiple of hash length.
    // The process is mostly the same we have in genesistool.cpp

    // Open the output file
    std::ofstream out_stream{file_name};
    out_stream << "/* Generated by Silkworm toolbox's extract headers */\n"
               << "#include <cstdint>\n"
               << "#include <cstddef>\n"
               << "static const uint64_t preverified_hashes_mainnet_internal[] = {" << std::endl;

    BlockNum block_max{silkworm::db::stages::read_stage_progress(txn, db::stages::kHeadersKey)};
    BlockNum max_height{0};
    auto hashes_table{db::open_cursor(txn, db::table::kCanonicalHashes)};

    for (BlockNum block_num = 0; block_num <= block_max; block_num += step) {
        auto block_key{db::block_key(block_num)};
        auto data{hashes_table.find(db::to_slice(block_key), false)};
        if (!data.done) {
            break;
        }

        const uint64_t* chuncks{reinterpret_cast<const uint64_t*>(db::from_slice(data.value).data())};
        out_stream << "   ";
        for (int i = 0; i < 4; ++i) {
            std::string hex{to_hex(chuncks[i], true)};
            out_stream << hex << ",";
        }
        out_stream << std::endl;
        max_height = block_num;
    }

    out_stream
        << "};\n"
        << "const uint64_t* preverified_hashes_mainnet_data(){return &preverified_hashes_mainnet_internal[0];}\n"
        << "size_t sizeof_preverified_hashes_mainnet_data(){return sizeof(preverified_hashes_mainnet_internal);}\n"
        << "uint64_t preverified_hashes_mainnet_height(){return " << max_height << "ull;}\n"
        << std::endl;
    out_stream.close();
}

void do_trie_account_analysis(db::EnvConfig& config) {
    static std::string fmt_hdr{" %-24s %=50s "};

    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{silkworm::db::open_env(config)};
    auto txn{env.start_read()};

    std::cout << "\n"
              << (boost::format(fmt_hdr) % "Table name" % "%") << "\n"
              << (boost::format(fmt_hdr) % std::string(24, '-') % std::string(50, '-')) << "\n"
              << (boost::format(" %-24s ") % db::table::kTrieOfAccounts.name) << std::flush;

    std::map<size_t, size_t> histogram;
    auto code_cursor{db::open_cursor(txn, db::table::kTrieOfAccounts)};

    Progress progress{50};
    size_t total_entries{txn.get_map_stat(code_cursor.map()).ms_entries};
    progress.set_task_count(total_entries);
    size_t batch_size{progress.get_increment_count()};

    code_cursor.to_first();
    cursor_for_each(code_cursor,
                    [&histogram, &batch_size, &progress](ByteView key, ByteView) {
                        ++histogram[key.length()];
                        if (!--batch_size) {
                            progress.set_current(progress.get_current() + progress.get_increment_count());
                            std::cout << progress.print_interval('.') << std::flush;
                            batch_size = progress.get_increment_count();
                        }
                    });

    progress.set_current(total_entries);
    std::cout << progress.print_interval('.') << std::endl;

    if (!histogram.empty()) {
        std::cout << (boost::format(" %-4s %8s") % "Size" % "Count") << "\n"
                  << (boost::format(" %-4s %8s") % std::string(4, '-') % std::string(8, '-')) << std::endl;
        for (const auto& [size, usage_count] : histogram) {
            std::cout << (boost::format(" %4u %8u") % size % usage_count) << std::endl;
        }
    }
    std::cout << "\n"
              << std::endl;
}

void do_trie_scan(db::EnvConfig& config, bool del) {
    auto env{silkworm::db::open_env(config)};
    auto txn{env.start_write()};
    std::vector<db::MapConfig> tables{db::table::kTrieOfAccounts, db::table::kTrieOfStorage};
    size_t counter{1};

    for (const auto& map_config : tables) {
        if (SignalHandler::signalled()) {
            break;
        }
        db::PooledCursor cursor(txn, map_config);
        std::cout << " Scanning " << map_config.name << std::endl;
        auto data{cursor.to_first(false)};
        while (data) {
            if (data.value.empty()) {
                std::cout << "Empty value at key " << to_hex(db::from_slice(data.key), true) << std::endl;
                if (del) {
                    cursor.erase();
                }
            }
            data = cursor.to_next(false);
            if (!--counter) {
                counter = 128;
                if (SignalHandler::signalled()) {
                    break;
                }
            }
        }
    }
    if (!SignalHandler::signalled()) {
        txn.commit();
    }
    std::cout << "\n"
              << std::endl;
}

void do_trie_integrity(db::EnvConfig& config, bool with_state_coverage, bool continue_scan, bool sanitize) {
    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    using namespace std::chrono_literals;
    std::chrono::time_point start{std::chrono::steady_clock::now()};

    auto env{silkworm::db::open_env(config)};
    auto txn{env.start_write()};

    std::string source{db::table::kTrieOfAccounts.name};

    bool is_healthy{true};
    db::PooledCursor trie_cursor1(txn, db::table::kTrieOfAccounts);
    db::PooledCursor trie_cursor2(txn, db::table::kTrieOfAccounts);
    db::PooledCursor state_cursor(txn, db::table::kHashedAccounts);
    size_t prefix_len{0};

    Bytes buffer;
    buffer.reserve(256);

    // First loop Accounts; Second loop Storage
    for (int loop_id{0}; loop_id < 2; ++loop_id) {
        if (loop_id != 0) {
            source = std::string(db::table::kTrieOfStorage.name);
            trie_cursor1.bind(txn, db::table::kTrieOfStorage);
            trie_cursor2.bind(txn, db::table::kTrieOfStorage);
            state_cursor.bind(txn, db::table::kHashedStorage);
            prefix_len = db::kHashedStoragePrefixLength;
        }

        SILK_INFO << "Checking ..." << log::Args{"source", source, "state", (with_state_coverage ? "true" : "false")};

        auto data1{trie_cursor1.to_first(false)};

        while (data1) {
            auto data1_k{db::from_slice(data1.key)};
            auto data1_v{db::from_slice(data1.value)};
            auto node_k{data1_k.substr(prefix_len)};

            // Only unmarshal relevant data without copy on read
            if (data1_v.length() < 6) {
                throw std::runtime_error("At key " + to_hex(data1_k, true) + " invalid value length " +
                                         std::to_string(data1_v.length()) + ". Expected >= 6");
            } else if ((data1_v.length() - 6) % kHashLength != 0) {
                throw std::runtime_error("At key " + to_hex(data1_k, true) + " invalid hashes count " +
                                         std::to_string(data1_v.length() - 6) + ". Expected multiple of " +
                                         std::to_string(kHashLength));
            }

            const auto node_state_mask{endian::load_big_u16(&data1_v[0])};
            const auto node_tree_mask{endian::load_big_u16(&data1_v[2])};
            const auto node_hash_mask{endian::load_big_u16(&data1_v[4])};
            bool node_has_root{false};

            if (!node_state_mask) {
                // This node should not be here as it does not point to anything
                std::string what{"At key " + to_hex(data1_k, true) +
                                 " node with nil state_mask. Does not point to anything. Shouldn't be here"};
                if (!continue_scan) {
                    throw std::runtime_error(what);
                }
                is_healthy = false;
                std::cout << " " << what << std::endl;
            }

            if (!trie::is_subset(node_tree_mask, node_state_mask)) {
                throw std::runtime_error("At key " + to_hex(data1_k, true) + " tree mask " +
                                         std::bitset<16>(node_tree_mask).to_string() + " is not subset of state mask " +
                                         std::bitset<16>(node_state_mask).to_string());
            }
            if (!trie::is_subset(node_hash_mask, node_state_mask)) {
                throw std::runtime_error("At key " + to_hex(data1_k, true) + " hash mask " +
                                         std::bitset<16>(node_hash_mask).to_string() + " is not subset of state mask " +
                                         std::bitset<16>(node_state_mask).to_string());
            }

            data1_v.remove_prefix(6);
            auto expected_hashes_count{static_cast<size_t>(std::popcount(node_hash_mask))};
            auto effective_hashes_count{data1_v.length() / kHashLength};
            if (!(effective_hashes_count == expected_hashes_count ||
                  effective_hashes_count == expected_hashes_count + 1u)) {
                std::string what{"At key " + to_hex(data1_k, true) + " invalid hashes count " +
                                 std::to_string(effective_hashes_count) + ". Expected " +
                                 std::to_string(expected_hashes_count) + " from mask " +
                                 std::bitset<16>(node_hash_mask).to_string()};

                if (!continue_scan) {
                    throw std::runtime_error(what);
                }
                is_healthy = false;
                std::cout << " " << what << std::endl;
            } else {
                node_has_root = (effective_hashes_count == expected_hashes_count + 1u);
            }

            /*
             * Nodes with a key length == 0 are root nodes and MUST have a root hash
             */
            if (node_k.empty() && !node_has_root) {
                std::string what{"At key " + to_hex(data1_k, true) + " found root node without root hash"};
                if (!continue_scan) {
                    throw std::runtime_error(what);
                }
                is_healthy = false;
                std::cout << " " << what << std::endl;
            } else if (!node_k.empty() && node_has_root) {
                log::Warning("Unexpected root hash", {"key", to_hex(data1_k, true)});
            }

            /*
             * Check children (if any)
             * Each bit set in tree_mask must point to an existing child
             * Example :
             * Current key       : 010203
             * Current tree_mask : 0b0000000000000100
             * Children key      : 01020302 must exist
             *
             * Current key       : 010203
             * Current tree_mask : 0b0000000000100000
             * Children key      : 01020305 must exist
             */

            if (node_tree_mask) {
                buffer.assign(data1_k).push_back('\0');
                for (int i{std::countr_zero(node_tree_mask)}, e{std::bit_width(node_tree_mask)}; i < e; ++i) {
                    if (((1 << i) & node_tree_mask) == 0) {
                        continue;
                    }
                    buffer.back() = static_cast<uint8_t>(i);
                    auto data2{trie_cursor2.lower_bound(db::to_slice(buffer), false)};
                    if (!data2) {
                        throw std::runtime_error("At key " + to_hex(data1_k, true) + " tree mask is " +
                                                 std::bitset<16>(node_tree_mask).to_string() +
                                                 " but there is no child " + std::to_string(i) +
                                                 " in db. LTE found is : null");
                    } else {
                        auto data2_k{db::from_slice(data2.key)};

                        if (!data2_k.starts_with(buffer)) {
                            throw std::runtime_error("At key " + to_hex(data1_k, true) + " tree mask is " +
                                                     std::bitset<16>(node_tree_mask).to_string() +
                                                     " but there is no child " + std::to_string(i) +
                                                     " in db. LTE found is : " + to_hex(data2_k, true));
                        }
                    }
                }
            }

            /*
             * Check parents (if not root)
             * Whether node key length > 1 then at least one parent with a key length shorter than this one must exist
             * Note : length is expressed in nibbles count
             * Example:
             * When node key : 01020304
             * Must find one key in list {010203; 0102} (max jump of 2)
             */

            if (!node_k.empty()) {
                bool found{false};

                for (size_t i{data1_k.size() - 1}; i >= prefix_len && !found; --i) {
                    auto parent_seek_key{data1_k.substr(0, i)};
                    auto data2{trie_cursor2.find(db::to_slice(parent_seek_key), false)};
                    if (!data2) {
                        continue;
                    }
                    found = true;
                    const auto data2_v{db::from_slice(data2.value)};
                    const auto parent_tree_mask{endian::load_big_u16(&data2_v[2])};
                    const auto parent_child_id{static_cast<int>(data1_k[i])};
                    const auto parent_has_tree_bit{(parent_tree_mask & (1 << parent_child_id)) != 0};
                    if (!parent_has_tree_bit) {
                        found = false;
                        if (sanitize) {
                            SILK_WARN << "Erasing orphan" << log::Args{"key", to_hex(data1_k, true)};
                            trie_cursor1.erase();
                            goto next_node;
                        }
                        std::string what{"At key " + to_hex(data1_k, true) + " found parent key " +
                                         to_hex(parent_seek_key, true) +
                                         " with tree mask : " + std::bitset<16>(parent_tree_mask).to_string() +
                                         " and no bit set at position " + std::to_string(parent_child_id)};
                        if (!continue_scan) {
                            throw std::runtime_error(what);
                        }
                        is_healthy = false;
                        std::cout << " " << what << std::endl;
                    }
                }

                if (!found) {
                    if (sanitize) {
                        SILK_WARN << "Erasing orphan" << log::Args{"key", to_hex(data1_k, true)};
                        trie_cursor1.erase();
                        goto next_node;
                    }
                    std::string what{"At key " + to_hex(data1_k, true) + " no parent found"};
                    if (!continue_scan) {
                        throw std::runtime_error(what);
                    }
                    is_healthy = false;
                    std::cout << " " << what << std::endl;
                }
            }

            /*
             * Slow check for state coverage
             * Whether the node has any hash_state bit set then we must ensure the bits point to
             * an existing hashed state (either account or storage)
             *
             * Example:
             * Current key        : 010203
             * Current state_mask : 0b0000000000000001
             * New Nibbled key    : 01020300
             * Packed key         : 1230
             * A state with prefix in range [1230 ... 1231) must exist
             */

            if (with_state_coverage && node_state_mask) {
                // Buffer is used to build seek key
                buffer.assign(data1_k.substr(prefix_len));
                buffer.push_back('\0');

                auto bits_to_match{buffer.length() * 4};

                // >>> See Erigon's /ethdb/kv_util.go::BytesMask
                uint8_t mask{0xff};
                auto fixed_bytes{(bits_to_match + 7) / 8};
                auto shift_bits{bits_to_match & 7};
                if (shift_bits != 0) {
                    mask <<= (8 - shift_bits);
                }
                // <<< See Erigon's ByteMask

                for (int i{std::countr_zero(node_state_mask)}, e{std::bit_width(node_state_mask)}; i < e; ++i) {
                    if (((1 << i) & node_state_mask) == 0) {
                        continue;
                    }

                    bool found{false};
                    buffer.back() = static_cast<uint8_t>(i);

                    Bytes seek{trie::pack_nibbles(buffer)};

                    // On first loop we search HashedAccounts (which is not dupsorted)
                    if (!loop_id) {
                        auto data3{state_cursor.lower_bound(db::to_slice(seek), false)};
                        if (data3) {
                            auto data3_k{db::from_slice(data3.key)};
                            if (data3_k.length() >= fixed_bytes) {
                                found = (bits_to_match == 0 ||
                                         ((data3_k.substr(0, fixed_bytes - 1) == seek.substr(0, fixed_bytes - 1)) &&
                                          ((data3_k[fixed_bytes - 1] & mask) == (seek[fixed_bytes - 1] & mask))));
                            }
                        }
                        if (!found) {
                            std::string what{"At key " + to_hex(data1_k, true) + " state mask is " +
                                             std::bitset<16>(node_state_mask).to_string() + " but there is no child " +
                                             std::to_string(i) + "," + to_hex(seek, true) + " in hashed state"};
                            if (data3) {
                                auto data3_k{db::from_slice(data3.key)};
                                what.append(" found instead " + to_hex(data3_k, true));
                            }
                            throw std::runtime_error(what);
                        }
                    } else {
                        // On second loop we search HashedStorage (which is dupsorted)
                        auto data3{state_cursor.lower_bound_multivalue(db::to_slice(data1_k.substr(0, prefix_len)),
                                                                       db::to_slice(seek), false)};
                        if (data3) {
                            auto data3_v{db::from_slice(data3.value)};
                            if (data3_v.length() >= fixed_bytes) {
                                found = (bits_to_match == 0 ||
                                         ((data3_v.substr(0, fixed_bytes - 1) == seek.substr(0, fixed_bytes - 1)) &&
                                          ((data3_v[fixed_bytes - 1] & mask) == (seek[fixed_bytes - 1] & mask))));
                            }
                        }
                        if (!found) {
                            std::string what{"At key " + to_hex(data1_k, true) + " state mask is " +
                                             std::bitset<16>(node_state_mask).to_string() + " but there is no child " +
                                             std::to_string(i) + "," + to_hex(seek, true) + " in state"};
                            if (data3) {
                                auto data3_k{db::from_slice(data3.key)};
                                auto data3_v{db::from_slice(data3.value)};
                                what.append(" found instead " + to_hex(data3_k, true) + to_hex(data3_v, false));
                            }
                            throw std::runtime_error(what);
                        }
                    }
                }
            }

            if (std::chrono::time_point now{std::chrono::steady_clock::now()}; now - start >= 10s) {
                if (SignalHandler::signalled()) {
                    throw std::runtime_error("Interrupted");
                }
                std::swap(start, now);
                log::Info("Checking ...", {"source", source, "key", to_hex(data1_k, true)});
            }

        next_node:
            data1 = trie_cursor1.to_next(false);
        }
    }
    if (!is_healthy) {
        throw std::runtime_error("Check failed");
    }

    SILK_INFO << "Integrity check" << log::Args{"status", "ok"};
    SILK_INFO << "Closing db" << log::Args{"path", env.get_path().string()};
    txn.commit();
    env.close();
}

void do_trie_reset(db::EnvConfig& config, bool always_yes) {
    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    if (!always_yes) {
        if (!user_confirmation()) {
            return;
        }
    }

    auto env{silkworm::db::open_env(config)};
    db::RWTxnManaged txn{env};
    SILK_INFO << "Clearing ..." << log::Args{"table", db::table::kTrieOfAccounts.name};
    txn->clear_map(db::table::kTrieOfAccounts.name);
    SILK_INFO << "Clearing ..." << log::Args{"table", db::table::kTrieOfStorage.name};
    txn->clear_map(db::table::kTrieOfStorage.name);
    SILK_INFO << "Setting progress ..." << log::Args{"key", db::stages::kIntermediateHashesKey, "value", "0"};
    db::stages::write_stage_progress(txn, db::stages::kIntermediateHashesKey, 0);
    SILK_INFO << "Committing ..." << log::Args{};
    txn.commit_and_renew();
    SILK_INFO << "Closing db" << log::Args{"path", env.get_path().string()};
    env.close();
}

void do_trie_root(db::EnvConfig& config) {
    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{silkworm::db::open_env(config)};
    db::ROTxnManaged txn{env};
    db::PooledCursor trie_accounts(txn, db::table::kTrieOfAccounts);
    std::string source{db::table::kTrieOfAccounts.name};

    // Retrieve expected state root
    auto hashstate_stage_progress{db::stages::read_stage_progress(txn, db::stages::kHashStateKey)};
    auto intermediate_hashes_stage_progress{db::stages::read_stage_progress(txn, db::stages::kIntermediateHashesKey)};
    if (hashstate_stage_progress != intermediate_hashes_stage_progress) {
        throw std::runtime_error("HashState and Intermediate hashes stage progresses do not match");
    }
    auto header_hash{db::read_canonical_header_hash(txn, hashstate_stage_progress)};
    auto header{db::read_header(txn, hashstate_stage_progress, header_hash->bytes)};
    auto expected_state_root{header->state_root};

    trie::PrefixSet empty_changes{};  // We need this to tell we have no changes. If nullptr means full regen
    trie::HashBuilder hash_builder;

    trie::TrieCursor trie_cursor{trie_accounts, &empty_changes};
    for (auto trie_data{trie_cursor.to_prefix({})}; trie_data.key.has_value(); trie_data = trie_cursor.to_next()) {
        SILKWORM_ASSERT(!trie_data.first_uncovered.has_value());  // Means skip state
        SILK_INFO << "Trie" << log::Args{"key", to_hex(trie_data.key.value(), true), "hash", to_hex(trie_data.hash.value(), true)};
        auto& hash = trie_data.hash.value();
        hash_builder.add_branch_node(trie_data.key.value(), hash, false);
        if (SignalHandler::signalled()) {
            throw std::runtime_error("Interrupted");
        }
        if (trie_data.key->empty()) {
            break;  // just added root node
        }
    }

    auto computed_state_root{hash_builder.root_hash()};
    if (computed_state_root != expected_state_root) {
        log::Error("State root",
                   {"expected", to_hex(expected_state_root, true), "got", to_hex(hash_builder.root_hash(), true)});
    } else {
        log::Info("State root " + to_hex(computed_state_root, true));
    }
}

void do_reset_to_download(db::EnvConfig& config, bool keep_senders) {
    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    // Are you really sure ?
    if (!user_confirmation("Are you definitely sure ?")) {
        return;
    }

    log::Info() << "Ok... you say it. Please be patient...";

    auto env{silkworm::db::open_env(config)};
    db::RWTxnManaged txn(env);

    StopWatch sw(/*auto_start=*/true);
    // Void finish stage
    db::stages::write_stage_progress(txn, db::stages::kFinishKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kFinishKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void TxLookup stage
    SILK_INFO << db::stages::kTxLookupKey << log::Args{"table", db::table::kTxLookup.name} << "truncating ...";
    db::PooledCursor source(*txn, db::table::kTxLookup);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kTxLookupKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kTxLookupKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kTxLookupKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void LogIndex stage
    SILK_INFO << db::stages::kLogIndexKey << log::Args{"table", db::table::kLogTopicIndex.name} << " truncating ...";
    source.bind(*txn, db::table::kLogTopicIndex);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kLogIndexKey << log::Args{"table", db::table::kLogAddressIndex.name} << " truncating ...";
    source.bind(*txn, db::table::kLogAddressIndex);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kLogIndexKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kLogIndexKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kLogIndexKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void HistoryIndex (StorageHistoryIndex + AccountHistoryIndex) stage
    SILK_INFO << db::stages::kStorageHistoryIndexKey << log::Args{"table", db::table::kStorageHistory.name} << " truncating ...";
    source.bind(*txn, db::table::kStorageHistory);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kAccountHistoryIndexKey << log::Args{"table", db::table::kAccountHistory.name} << " truncating ...";
    source.bind(*txn, db::table::kAccountHistory);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kStorageHistoryIndexKey, 0);
    db::stages::write_stage_progress(txn, db::stages::kAccountHistoryIndexKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kStorageHistoryIndexKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kAccountHistoryIndexKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kStorageHistoryIndexKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    SILK_INFO << db::stages::kAccountHistoryIndexKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void HashState stage
    SILK_INFO << db::stages::kHashStateKey << log::Args{"table", db::table::kHashedCodeHash.name} << " truncating ...";
    source.bind(*txn, db::table::kHashedCodeHash);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kHashStateKey << log::Args{"table", db::table::kHashedStorage.name} << " truncating ...";
    source.bind(*txn, db::table::kHashedStorage);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kHashStateKey << log::Args{"table", db::table::kHashedAccounts.name} << " truncating ...";
    source.bind(*txn, db::table::kHashedAccounts);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kHashStateKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kHashStateKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kHashStateKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void Intermediate Hashes stage
    SILK_INFO << db::stages::kIntermediateHashesKey << log::Args{"table", db::table::kTrieOfStorage.name} << " truncating ...";
    source.bind(*txn, db::table::kTrieOfStorage);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kIntermediateHashesKey << log::Args{"table", db::table::kTrieOfAccounts.name} << " truncating ...";
    source.bind(*txn, db::table::kTrieOfAccounts);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kIntermediateHashesKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kIntermediateHashesKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void Execution stage
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kBlockReceipts.name} << " truncating ...";
    source.bind(*txn, db::table::kBlockReceipts);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kLogs.name} << " truncating ...";
    source.bind(*txn, db::table::kLogs);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kIncarnationMap.name} << " truncating ...";
    source.bind(*txn, db::table::kIncarnationMap);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kCode.name} << " truncating ...";
    source.bind(*txn, db::table::kCode);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kPlainCodeHash.name} << " truncating ...";
    source.bind(*txn, db::table::kPlainCodeHash);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kAccountChangeSet.name} << " truncating ...";
    source.bind(*txn, db::table::kAccountChangeSet);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kStorageChangeSet.name} << " truncating ...";
    source.bind(*txn, db::table::kStorageChangeSet);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kPlainState.name} << " truncating ...";
    source.bind(*txn, db::table::kPlainState);
    txn->clear_map(source.map());
    txn.commit_and_renew();

    {
        SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kPlainState.name} << " redo genesis allocations ...";
        // Read chain ID from database
        const auto chain_config{db::read_chain_config(txn)};
        ensure(chain_config.has_value(), "cannot read chain configuration from database");
        // Read genesis data from embedded file
        auto source_data{read_genesis_data(chain_config->chain_id)};
        // Parse genesis JSON data
        // N.B. = instead of {} initialization due to https://github.com/nlohmann/json/issues/2204
        auto genesis_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);
        db::initialize_genesis_allocations(txn, genesis_json);
        txn.commit_and_renew();
    }

    db::stages::write_stage_progress(txn, db::stages::kExecutionKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kExecutionKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kExecutionKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};

    if (!keep_senders) {
        // Void Senders stage
        SILK_INFO << db::stages::kSendersKey << log::Args{"table", db::table::kSenders.name} << " truncating ...";
        source.bind(*txn, db::table::kSenders);
        txn->clear_map(source.map());
        db::stages::write_stage_progress(txn, db::stages::kSendersKey, 0);
        db::stages::write_stage_prune_progress(txn, db::stages::kSendersKey, 0);
        txn.commit_and_renew();
        SILK_INFO << db::stages::kSendersKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
        if (SignalHandler::signalled()) throw std::runtime_error("Aborted");
    }

    auto [tp, _]{sw.stop()};
    auto duration{sw.since_start(tp)};
    SILK_INFO << "All done" << log::Args{"in", StopWatch::format(duration)};
}

int main(int argc, char* argv[]) {
    SignalHandler::init();

    CLI::App app_main("Silkworm db tool");
    app_main.get_formatter()->column_width(50);
    app_main.require_subcommand(1);  // At least 1 subcommand is required
    log::Settings log_settings{};    // Holds logging settings

    /*
     * Database options (path required)
     */
    auto db_opts = app_main.add_option_group("Db", "Database options");
    db_opts->get_formatter()->column_width(35);
    auto shared_opt = db_opts->add_flag("--shared", "Open database in shared mode");
    auto exclusive_opt = db_opts->add_flag("--exclusive", "Open database in exclusive mode")->excludes(shared_opt);

    auto db_opts_paths = db_opts->add_option_group("Path", "Database path")->require_option(1);
    db_opts_paths->get_formatter()->column_width(35);

    auto chaindata_opt = db_opts_paths->add_option("--chaindata", "Path to directory for mdbx.dat");
    auto datadir_opt = db_opts_paths->add_option("--datadir", "Path to data directory")->excludes(chaindata_opt);

    /*
     * Common opts and flags
     */
    auto app_yes_opt = app_main.add_flag("-Y,--yes", "Assume yes to all requests of confirmation");
    auto app_dry_opt = app_main.add_flag("--dry", "Don't commit to db. Only simulate");

    /*
     * Subcommands
     */
    // List tables and gives info about storage
    auto cmd_tables = app_main.add_subcommand("tables", "List db and tables info");
    auto cmd_tables_scan_opt = cmd_tables->add_flag("--scan", "Scan real data size (long)");

    // List infor of free pages with optional detail
    auto cmd_freelist = app_main.add_subcommand("freelist", "Print free pages info");
    auto freelist_detail_opt = cmd_freelist->add_flag("--detail", "Gives detail for each FREE_DBI record");

    // Read db schema
    auto cmd_schema = app_main.add_subcommand("schema", "Reports schema version of Silkworm database");

    // List stages keys and their heights
    auto cmd_stages = app_main.add_subcommand("stages", "List stages and their actual heights");

    // List migration keys
    auto cmd_migrations = app_main.add_subcommand("migrations", "List migrations");

    // Clear table tool
    auto cmd_clear = app_main.add_subcommand("clear", "Empties or drops provided named table(s)");
    std::vector<std::string> cmd_clear_names;
    cmd_clear->add_option("--names", cmd_clear_names, "Name(s) of table to clear")->required();
    auto cmd_clear_drop_opt = cmd_clear->add_flag("--drop", "Drop table instead of emptying it");

    // Compact database file
    auto cmd_compact = app_main.add_subcommand("compact", "Compacts an lmdb database");
    auto cmd_compact_workdir_opt = cmd_compact->add_option("--workdir", "Working directory")->required();
    auto cmd_compact_replace_opt = cmd_compact->add_flag("--replace", "Replace original file with compacted");
    auto cmd_compact_nobak_opt = cmd_compact->add_flag("--nobak", "Don't create a bak copy of original when replacing")
                                     ->needs(cmd_compact_replace_opt);

    // Copy database file or subset of tables
    auto cmd_copy = app_main.add_subcommand("copy", "Copies an entire Silkworm database or subset of tables")
                        ->excludes(app_dry_opt);
    auto cmd_copy_targetdir_opt = cmd_copy->add_option("--targetdir", "Target directory")->required();
    auto cmd_copy_target_create_opt = cmd_copy->add_flag("--create", "Create target db if not exists");
    auto cmd_copy_target_noempty_opt = cmd_copy->add_flag("--noempty", "Skip copy of empty tables");
    std::vector<std::string> cmd_copy_names, cmd_copy_xnames;
    cmd_copy->add_option("--tables", cmd_copy_names, "Copy only tables matching this list of names")
        ->capture_default_str();
    cmd_copy->add_option("--xtables", cmd_copy_xnames, "Don't copy tables matching this list of names")
        ->capture_default_str();

    // Compare the content of two databases
    auto cmd_compare = app_main.add_subcommand("compare", "Compare the content of two databases")
                           ->excludes(app_dry_opt);
    auto cmd_compare_datadir = cmd_compare->add_option("--other_datadir", "Path to other data directory")->required();
    auto cmd_compare_verbose = cmd_compare->add_flag("--verbose", "Print verbose output");
    auto cmd_compare_check_pages = cmd_compare->add_flag("--check_pages", "Check if b-tree page counters match");
    std::optional<std::string> cmd_compare_table;
    cmd_compare->add_option("--table", cmd_compare_table, "Name of specific table to compare")
        ->capture_default_str();

    // Stages tool
    auto cmd_stageset = app_main.add_subcommand("stage-set", "Sets a stage to a new height");
    auto cmd_stageset_name_opt = cmd_stageset->add_option("--name", "Name of the stage to set")->required();
    auto cmd_stageset_height_opt =
        cmd_stageset->add_option("--height", "Block height to set the stage to")->required()->check(CLI::Range(0u, UINT32_MAX));

    // Unwind tool
    auto cmd_staged_unwind = app_main.add_subcommand("unwind", "Unwind staged sync to a previous height");
    auto cmd_staged_unwind_height =
        cmd_staged_unwind->add_option("--height", "Block height to unwind the staged sync to")
            ->required()
            ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_staged_unwind_remove_blocks =
        cmd_staged_unwind->add_flag("--remove_blocks", "Remove block headers and bodies up to unwind point")
            ->capture_default_str();

    // Initialize with genesis tool
    auto cmd_initgenesis = app_main.add_subcommand("init-genesis", "Initialize a new db with genesis block");
    cmd_initgenesis->require_option(1);
    auto cmd_initgenesis_json_opt =
        cmd_initgenesis->add_option("--json", "Full path to genesis json file")->check(CLI::ExistingFile);

    auto cmd_initgenesis_chain_opt =
        cmd_initgenesis->add_option("--chain", "Name of the chain to initialize")
            ->excludes(cmd_initgenesis_json_opt)
            ->transform(CLI::Transformer(kKnownChainNameToId.to_std_map<std::string>(), CLI::ignore_case));

    // Read chain config held in db (if any)
    auto cmd_chainconfig = app_main.add_subcommand("chain-config", "Prints chain config held in database");

    // Print the list of canonical blocks in specified range
    auto cmd_canonical_blocks =
        app_main.add_subcommand("canonical_blocks", "Print canonical blocks from database in specified range");
    auto cmd_canonical_blocks_from = cmd_canonical_blocks->add_option("--from", "Block height to start with")
                                         ->required()
                                         ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_canonical_blocks_to = cmd_canonical_blocks->add_option("--to", "Block height to end with")
                                       ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_canonical_blocks_step = cmd_canonical_blocks->add_option("--step", "Step every this number of blocks")
                                         ->default_val("1")
                                         ->check(CLI::Range(1u, UINT32_MAX));

    // Print the list of saved blocks in specified range
    auto cmd_blocks = app_main.add_subcommand("blocks", "Print blocks from database in specified range");
    auto cmd_blocks_from = cmd_blocks->add_option("--from", "Block height to start with")
                               ->required()
                               ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_blocks_to = cmd_blocks->add_option("--to", "Block height to end with")
                             ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_blocks_step = cmd_blocks->add_option("--step", "Step every this number of blocks")
                               ->default_val("1")
                               ->check(CLI::Range(1u, UINT32_MAX));

    // Do first byte analytics on deployed contract codes
    auto cmd_first_byte_analysis = app_main.add_subcommand(
        "first-byte-analysis", "Prints an histogram analysis of first byte for deployed contracts");

    // Extract a list of historical headers in given file
    auto cmd_extract_headers = app_main.add_subcommand(
        "extract-headers", "Hard-code historical headers, from block zero to the highest available");
    auto cmd_extract_headers_file_opt = cmd_extract_headers->add_option("--file", "Output file")->required();
    auto cmd_extract_headers_step_opt = cmd_extract_headers->add_option("--step", "Step every this number of blocks")
                                            ->default_val("100000")
                                            ->check(CLI::Range(1u, UINT32_MAX));

    // Scan tries
    auto cmd_trie_scan = app_main.add_subcommand("trie-scan", "Scans tries for empty values");
    auto cmd_trie_scan_delete_opt = cmd_trie_scan->add_flag("--delete", "Delete");

    // Reset tries
    auto cmd_trie_reset = app_main.add_subcommand("trie-reset", "Resets stage_interhashes");

    // Trie integrity
    auto cmd_trie_integrity = app_main.add_subcommand("trie-integrity", "Checks trie integrity");
    auto cmd_trie_integrity_state_opt = cmd_trie_integrity->add_flag("--with-state", "Checks covered states (slower)");
    auto cmd_trie_integrity_continue_opt = cmd_trie_integrity->add_flag("--continue", "Keeps scanning on found errors");
    auto cmd_trie_integrity_sanitize_opt = cmd_trie_integrity->add_flag("--sanitize", "Clean orphan nodes");

    // Trie account analysis
    auto cmd_trie_account_analysis =
        app_main.add_subcommand("trie-account-analysis", "Trie account key sizes analysis");

    // Trie root hash verification
    auto cmd_trie_root = app_main.add_subcommand("trie-root", "Checks trie root");

    // Reset after download
    // Truncates all the work done beyond download stages
    auto cmd_reset_to_download =
        app_main.add_subcommand("reset-to-download", "Reset all work and data written after bodies download");
    auto cmd_reset_to_download_keep_senders_opt =
        cmd_reset_to_download->add_flag("--keep-senders", "Keep the recovered transaction senders");

    /*
     * Parse arguments and validate
     */
    CLI11_PARSE(app_main, argc, argv)

    auto data_dir_factory = [&chaindata_opt, &datadir_opt]() -> DataDirectory {
        if (*chaindata_opt) {
            fs::path p{chaindata_opt->as<std::string>()};
            return DataDirectory::from_chaindata(p);
        }
        fs::path p{datadir_opt->as<std::string>()};
        return DataDirectory(p, false);
    };

    try {
        // Set origin data_dir
        DataDirectory data_dir{data_dir_factory()};

        if (!*cmd_initgenesis) {
            if (!data_dir.chaindata().exists() || data_dir.is_pristine()) {
                std::cerr << "\n Directory " << data_dir.chaindata().path().string() << " does not exist or is empty"
                          << std::endl;
                return -1;
            }
            auto mdbx_path{db::get_datafile_path(data_dir.chaindata().path())};
            if (!fs::exists(mdbx_path) || !fs::is_regular_file(mdbx_path)) {
                std::cerr << "\n Directory " << data_dir.chaindata().path().string() << " does not contain "
                          << db::kDbDataFileName << std::endl;
                return -1;
            }
        }

        db::EnvConfig src_config{data_dir.chaindata().path().string()};
        src_config.shared = static_cast<bool>(*shared_opt);
        src_config.exclusive = static_cast<bool>(*exclusive_opt);

        // Execute subcommand actions
        if (*cmd_tables) {
            if (*cmd_tables_scan_opt) {
                do_scan(src_config);
            } else {
                do_tables(src_config);
            }
        } else if (*cmd_freelist) {
            do_freelist(src_config, static_cast<bool>(*freelist_detail_opt));
        } else if (*cmd_schema) {
            do_schema(src_config);
        } else if (*cmd_stages) {
            do_stages(src_config);
        } else if (*cmd_migrations) {
            do_migrations(src_config);
        } else if (*cmd_clear) {
            do_clear(src_config, static_cast<bool>(*app_dry_opt), static_cast<bool>(*app_yes_opt), cmd_clear_names,
                     static_cast<bool>(*cmd_clear_drop_opt));
        } else if (*cmd_compact) {
            do_compact(src_config, cmd_compact_workdir_opt->as<std::string>(),
                       static_cast<bool>(*cmd_compact_replace_opt), static_cast<bool>(*cmd_compact_nobak_opt));
        } else if (*cmd_copy) {
            do_copy(src_config, cmd_copy_targetdir_opt->as<std::string>(),
                    static_cast<bool>(*cmd_copy_target_create_opt), static_cast<bool>(*cmd_copy_target_noempty_opt),
                    cmd_copy_names, cmd_copy_xnames);
        } else if (*cmd_compare) {
            compare(src_config, cmd_compare_datadir->as<std::filesystem::path>(), cmd_compare_check_pages->as<bool>(),
                    cmd_compare_verbose->as<bool>(), cmd_compare_table);
        } else if (*cmd_stageset) {
            do_stage_set(src_config, cmd_stageset_name_opt->as<std::string>(), cmd_stageset_height_opt->as<uint32_t>(),
                         static_cast<bool>(*app_dry_opt));
        } else if (*cmd_staged_unwind) {
            unwind(src_config, cmd_staged_unwind_height->as<uint32_t>(), static_cast<bool>(*cmd_staged_unwind_remove_blocks));
        } else if (*cmd_initgenesis) {
            do_init_genesis(data_dir, cmd_initgenesis_json_opt->as<std::string>(),
                            *cmd_initgenesis_chain_opt ? cmd_initgenesis_chain_opt->as<uint32_t>() : 0u,
                            static_cast<bool>(*app_dry_opt));
            if (*app_dry_opt) {
                std::cout << "\nGenesis initialization succeeded. Due to --dry flag no data is persisted\n"
                          << std::endl;
                fs::remove_all(data_dir.path());
            }
        } else if (*cmd_chainconfig) {
            do_chainconfig(src_config);
        } else if (*cmd_canonical_blocks) {
            print_canonical_blocks(src_config,
                                   cmd_canonical_blocks_from->as<BlockNum>(),
                                   cmd_canonical_blocks_to->as<std::optional<BlockNum>>(),
                                   cmd_canonical_blocks_step->as<uint64_t>());
        } else if (*cmd_blocks) {
            print_blocks(src_config, cmd_blocks_from->as<BlockNum>(), cmd_blocks_to->as<std::optional<BlockNum>>(),
                         cmd_blocks_step->as<uint64_t>());
        } else if (*cmd_first_byte_analysis) {
            do_first_byte_analysis(src_config);
        } else if (*cmd_extract_headers) {
            do_extract_headers(src_config, cmd_extract_headers_file_opt->as<std::string>(),
                               cmd_extract_headers_step_opt->as<uint32_t>());
        } else if (*cmd_trie_scan) {
            do_trie_scan(src_config, static_cast<bool>(*cmd_trie_scan_delete_opt));
        } else if (*cmd_trie_reset) {
            do_trie_reset(src_config, static_cast<bool>(*app_yes_opt));
        } else if (*cmd_trie_integrity) {
            do_trie_integrity(src_config, static_cast<bool>(*cmd_trie_integrity_state_opt),
                              static_cast<bool>(*cmd_trie_integrity_continue_opt),
                              static_cast<bool>(*cmd_trie_integrity_sanitize_opt));
        } else if (*cmd_trie_account_analysis) {
            do_trie_account_analysis(src_config);
        } else if (*cmd_trie_root) {
            do_trie_root(src_config);
        } else if (*cmd_reset_to_download) {
            do_reset_to_download(src_config, static_cast<bool>(*cmd_reset_to_download_keep_senders_opt));
        }

        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "\nError: " << ex.what() << "\n\n";
    } catch (...) {
        std::cerr << "\nUnexpected undefined error\n\n";
    }

    return -1;
}
