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
#include <string_view>

#include <CLI/CLI.hpp>
#include <boost/format.hpp>
#include <magic_enum.hpp>
#include <tl/expected.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/data_store.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/datastore/stage_scheduler.hpp>
#include <silkworm/db/freezer.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/prune_mode.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/infra/cli/common.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/active_component.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>
#include <silkworm/infra/test_util/task_runner.hpp>

namespace fs = std::filesystem;
using namespace silkworm;
using namespace silkworm::db;
using namespace silkworm::datastore::kvdb;

class Progress {
  public:
    explicit Progress(uint32_t width) : bar_width_{width}, percent_step_{100u / width} {};
    ~Progress() = default;

    //! Returns current progress percent
    uint32_t percent() const {
        if (!max_counter_) {
            return 100;
        }
        if (!current_counter_) {
            return 0;
        }
        return static_cast<uint32_t>(current_counter_ * 100 / max_counter_);
    }

    void step() { ++current_counter_; }
    void set_current(size_t count) { current_counter_ = std::max(count, current_counter_); }
    size_t get_current() const noexcept { return current_counter_; }
    size_t get_increment_count() const noexcept { return bar_width_ ? (max_counter_ / bar_width_) : 0u; }

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
        uint32_t num_chars{percentage / percent_step_};
        if (!num_chars) return "";
        uint32_t int_chars{num_chars - printed_bar_len_};
        if (!int_chars) return "";
        std::string ret(int_chars, c);
        printed_bar_len_ += int_chars;
        return ret;
    }

    [[maybe_unused]] std::string print_progress(char c = '.') const {
        uint32_t percentage{percent()};
        uint32_t num_chars{percentage / percent_step_};
        if (!num_chars) {
            return "";
        }
        std::string ret(num_chars, c);
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
    size_t pages() const noexcept {
        return stat.ms_branch_pages + stat.ms_leaf_pages + stat.ms_overflow_pages;
    }
    size_t size() const noexcept { return pages() * stat.ms_psize; }
};

bool operator==(const DbTableInfo& lhs, const DbTableInfo& rhs) {
    return lhs.name == rhs.name;
}

using DbComparisonResult = tl::expected<void, std::string>;

DbComparisonResult compare(const DbTableInfo& lhs, const DbTableInfo& rhs, bool check_layout) {
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
    if (lhs.stat.ms_psize != rhs.stat.ms_psize) {
        return tl::make_unexpected("db page mismatch: " + std::to_string(lhs.stat.ms_psize) +
                                   " vs " + std::to_string(rhs.stat.ms_psize));
    }
    if (lhs.info.flags != rhs.info.flags) {
        return tl::make_unexpected("flags mismatch: " + std::to_string(lhs.info.flags) + " vs " + std::to_string(rhs.info.flags));
    }
    if (check_layout) {
        if (lhs.stat.ms_depth != rhs.stat.ms_depth) {
            return tl::make_unexpected("btree height mismatch: " + std::to_string(lhs.stat.ms_depth) +
                                       " vs " + std::to_string(rhs.stat.ms_depth));
        }
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

void cursor_for_each(mdbx::cursor& cursor, WalkFuncRef walker) {
    const bool throw_notfound{false};
    auto data = cursor.eof() ? cursor.to_first(throw_notfound) : cursor.current(throw_notfound);
    while (data) {
        walker(from_slice(data.key), from_slice(data.value));
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

static void print_body(const BlockBodyForStorage& body) {
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
        std::cout << "Unexpected user input: " << user_input << "\n";
    } while (true);

    return matches[2].length() == 0;
}

void table_get(EnvConfig& config, const std::string& table, const std::optional<Bytes>& k, std::optional<BlockNum> block_num) {
    ensure(k.has_value() || block_num.has_value(), "You must specify either --key or --block");
    auto env = open_env(config);
    auto txn = env.start_read();
    ensure(has_map(txn, table.c_str()), [&table]() { return "Table " + table + " not found"; });
    ::mdbx::map_handle table_map = txn.open_map(table);
    const std::string_view key_identifier = block_num ? "block_key" : "key";
    const Bytes key = k.value_or(block_key(*block_num));
    ::mdbx::cursor_managed cursor = txn.open_cursor(table_map);
    const auto result = cursor.find(to_slice(key), /*throw_notfound=*/false);
    if (!result.done) {
        std::cout << key_identifier << "=" << to_hex(key) << " not found\n";
        return;
    }
    ensure(from_slice(result.key) == key, "key mismatch");
    const ByteView value = from_slice(result.value);
    std::cout << key_identifier << "=" << to_hex(key) << " has value: " << to_hex(value) << "\n";
}

void do_clear(EnvConfig& config, bool dry, bool always_yes, const std::vector<std::string>& table_names,
              bool drop) {
    config.readonly = false;

    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{open_env(config)};
    auto txn{env.start_write()};

    for (const auto& tablename : table_names) {
        if (!has_map(txn, tablename.c_str())) {
            std::cout << "Table " << tablename << " not found\n";
            continue;
        }

        mdbx::map_handle table_map{txn.open_map(tablename)};
        size_t rcount{txn.get_map_stat(table_map).ms_entries};

        if (!rcount && !drop) {
            std::cout << " Table " << tablename << " is already empty. Skipping\n";
            continue;
        }

        std::cout << "\n"
                  << (drop ? "Dropping" : "Emptying") << " table " << tablename << " (" << rcount << " records) "
                  << std::flush;

        if (!always_yes) {
            if (!user_confirmation()) {
                std::cout << "  Skipped.\n";
                continue;
            }
        }

        std::cout << (dry ? "Simulating commit ..." : "Committing ...") << "\n";

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
        size_t tx_id{0};
        std::memcpy(&tx_id, key.data(), sizeof(size_t));
        uint32_t page_count{0};
        std::memcpy(&page_count, value.data(), sizeof(uint32_t));
        size_t total_size = page_count * page_size;
        ret.pages += page_count;
        ret.size += total_size;
        ret.entries.push_back({tx_id, page_count, total_size});
    }};

    auto free_crs{txn.open_cursor(free_map)};
    cursor_for_each(free_crs, collect_func);

    return ret;
}

DbInfo get_tables_info(::mdbx::txn& txn) {
    DbInfo ret{};
    DbTableInfo* table{nullptr};

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

void do_scan(EnvConfig& config) {
    static std::string fmt_hdr{" %3s %-24s %=50s %13s %13s %13s"};

    auto env{open_env(config)};
    auto txn{env.start_read()};

    auto tables_info{get_tables_info(txn)};

    std::cout << "\n Database tables    : " << tables_info.tables.size() << "\n\n";

    if (!tables_info.tables.empty()) {
        std::cout << (boost::format(fmt_hdr) % "Dbi" % "Table name" % "Progress" % "Keys" % "Data" % "Total")
                  << "\n";
        std::cout << (boost::format(fmt_hdr) % std::string(3, '-') % std::string(24, '-') % std::string(50, '-') %
                      std::string(13, '-') % std::string(13, '-') % std::string(13, '-'))
                  << std::flush;

        for (DbTableInfo item : tables_info.tables) {
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
              << (SignalHandler::signalled() ? "Aborted" : "Done") << " !\n\n";
    txn.commit();
    env.close(config.shared);
}

void do_migrations(EnvConfig& config) {
    static std::string fmt_hdr{" %-24s"};
    static std::string fmt_row{" %-24s"};

    auto env{open_env(config)};
    auto txn{env.start_read()};

    if (!has_map(txn, table::kMigrations.name)) {
        throw std::runtime_error("Either not a Silkworm db or table " + std::string{table::kMigrations.name} +
                                 " not found");
    }

    auto crs{open_cursor(txn, table::kMigrations)};

    if (txn.get_map_stat(crs.map()).ms_entries) {
        std::cout << "\n"
                  << (boost::format(fmt_hdr) % "Migration Name") << "\n";
        std::cout << (boost::format(fmt_hdr) % std::string(24, '-')) << "\n";

        auto result{crs.to_first(/*throw_notfound =*/false)};
        while (result) {
            std::cout << (boost::format(fmt_row) % result.key.as_string()) << "\n";
            result = crs.to_next(/*throw_notfound =*/false);
        }
        std::cout << "\n\n";
    } else {
        std::cout << "\n There are no migrations to list\n\n";
    }

    txn.commit();
    env.close(config.shared);
}

void do_tables(EnvConfig& config) {
    static std::string fmt_hdr{" %3s %-26s %10s %2s %10s %10s %10s %12s %10s %10s"};
    static std::string fmt_row{" %3i %-26s %10u %2u %10u %10u %10u %12s %10s %10s"};

    auto env{open_env(config)};
    auto txn{env.start_read()};

    auto db_tables_info{get_tables_info(txn)};
    auto db_free_info{get_free_info(txn)};

    std::cout << "\n Database tables          : " << db_tables_info.tables.size() << "\n";
    std::cout << " Effective pruning        : " << read_prune_mode(txn).to_string() << "\n"
              << "\n";

    if (!db_tables_info.tables.empty()) {
        std::cout << (boost::format(fmt_hdr) % "Dbi" % "Table name" % "Records" % "D" % "Branch" % "Leaf" % "Overflow" %
                      "Size" % "Key" % "Value")
                  << "\n";
        std::cout << (boost::format(fmt_hdr) % std::string(3, '-') % std::string(26, '-') % std::string(10, '-') %
                      std::string(2, '-') % std::string(10, '-') % std::string(10, '-') % std::string(10, '-') %
                      std::string(12, '-') % std::string(10, '-') % std::string(10, '-'))
                  << "\n";

        for (auto& item : db_tables_info.tables) {
            auto key_mode = magic_enum::enum_name(item.info.key_mode());
            auto value_mode = magic_enum::enum_name(item.info.value_mode());
            std::cout << (boost::format(fmt_row) % item.id % item.name % item.stat.ms_entries % item.stat.ms_depth %
                          item.stat.ms_branch_pages % item.stat.ms_leaf_pages % item.stat.ms_overflow_pages %
                          human_size(item.size()) % key_mode % value_mode)
                      << "\n";
        }
    }

    std::cout << "\n"
              << " Database file size   (A) : " << (boost::format("%13s") % human_size(db_tables_info.file_size)) << "\n"
              << " Data pages count         : " << (boost::format("%13u") % db_tables_info.pages) << "\n"
              << " Data pages size      (B) : " << (boost::format("%13s") % human_size(db_tables_info.size)) << "\n"
              << " Free pages count         : " << (boost::format("%13u") % db_free_info.pages) << "\n"
              << " Free pages size      (C) : " << (boost::format("%13s") % human_size(db_free_info.size)) << "\n"
              << " Reclaimable space        : "
              << (boost::format("%13s") % human_size(db_tables_info.file_size - db_tables_info.size + db_free_info.size))
              << " == A - B + C \n\n";

    txn.commit();
    env.close(config.shared);
}

void do_freelist(EnvConfig& config, bool detail) {
    static std::string fmt_hdr{"%9s %9s %12s"};
    static std::string fmt_row{"%9u %9u %12s"};

    auto env{open_env(config)};
    auto txn{env.start_read()};

    auto db_free_info{get_free_info(txn)};
    if (!db_free_info.entries.empty() && detail) {
        std::cout << "\n"
                  << (boost::format(fmt_hdr) % "TxId" % "Pages" % "Size") << "\n"
                  << (boost::format(fmt_hdr) % std::string(9, '-') % std::string(9, '-') % std::string(12, '-'))
                  << "\n";
        for (auto& item : db_free_info.entries) {
            std::cout << (boost::format(fmt_row) % item.id % item.pages % human_size(item.size)) << "\n";
        }
    }
    std::cout << "\n Record count         : " << boost::format("%13u") % db_free_info.entries.size() << "\n"
              << " Free pages count     : " << boost::format("%13u") % db_free_info.pages << "\n"
              << " Free pages size      : " << boost::format("%13s") % human_size(db_free_info.size) << "\n\n";

    txn.commit();
    env.close(config.shared);
}

void do_schema(EnvConfig& config, bool force_update) {
    auto env{open_env(config)};
    RWTxnManaged txn{env};

    auto schema_version{read_schema_version(txn)};
    if (!schema_version.has_value()) {
        throw std::runtime_error("Not a Silkworm db or no schema version found");
    }
    std::cout << "Database schema version: " << schema_version->to_string() << "\n";

    if (force_update) {
        write_schema_version(txn, table::kRequiredSchemaVersion);
        txn.commit_and_stop();
        std::cout << "New database schema version: " << table::kRequiredSchemaVersion.to_string() << "\n";
    }
}

void do_compact(EnvConfig& config, const std::string& work_dir, bool replace, bool nobak) {
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

    fs::path target_file_path{work_path / fs::path(kDbDataFileName)};
    if (fs::exists(target_file_path)) {
        throw std::runtime_error("Directory " + work_path.string() + " already contains an " +
                                 std::string(kDbDataFileName) + " file");
    }

    auto env{open_env(config)};

    // Determine file size of origin db
    size_t src_filesize{env.get_info().mi_geo.current};

    // Ensure target working directory has enough free space
    // at least the size of origin db
    auto target_space = fs::space(target_file_path.parent_path());
    if (target_space.free <= src_filesize) {
        throw std::runtime_error("Insufficient disk space on working directory's partition");
    }

    std::cout << "\n Compacting database from " << config.path << "\n into " << target_file_path
              << "\n Please be patient as there is no progress report ...\n";
    env.copy(/*destination*/ target_file_path.string(), /*compactify*/ true, /*forcedynamic*/ true);
    std::cout << "\n Database compaction " << (SignalHandler::signalled() ? "aborted !" : "completed ...") << "\n";
    env.close();

    if (!SignalHandler::signalled()) {
        // Do we have a valid compacted file on disk ?
        // replace source with target
        if (!fs::exists(target_file_path)) {
            throw std::runtime_error("Can't locate compacted database");
        }

        // Do we have to replace original file ?
        if (replace) {
            auto source_file_path{get_datafile_path(fs::path(config.path))};
            // Create a backup copy before replacing ?
            if (!nobak) {
                std::cout << " Creating backup copy of origin database ...\n";
                std::string src_file_back{kDbDataFileName};
                src_file_back.append(".bak");
                fs::path src_path_bak{source_file_path.parent_path() / fs::path{src_file_back}};
                if (fs::exists(src_path_bak)) {
                    fs::remove(src_path_bak);
                }
                fs::rename(source_file_path, src_path_bak);
            }

            std::cout << " Replacing origin database with compacted ...\n";
            if (fs::exists(source_file_path)) {
                fs::remove(source_file_path);
            }
            fs::rename(target_file_path, source_file_path);
        }
    }
}

void do_copy(EnvConfig& src_config, const std::string& target_dir, bool create, bool noempty,
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
    EnvConfig tgt_config{target_path.string()};
    tgt_config.exclusive = true;
    fs::path target_file_path{target_path / fs::path(kDbDataFileName)};
    if (!fs::exists(target_file_path)) {
        tgt_config.create = true;
    }

    // Source db
    auto src_env{open_env(src_config)};
    auto src_txn{src_env.start_read()};

    // Target db
    auto tgt_env{open_env(tgt_config)};
    auto tgt_txn{tgt_env.start_write()};

    // Get free info and tables from both source and target environment
    auto source_db_info = get_tables_info(src_txn);
    auto target_db_info = get_tables_info(tgt_txn);

    // Check source db has tables to copy besides the two system tables
    if (source_db_info.tables.size() < 3) {
        throw std::runtime_error("Source db has no tables to copy.");
    }

    size_t bytes_written{0};
    std::cout << boost::format(" %-24s %=50s") % "Table" % "Progress\n";
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
        MDBX_put_flags_t put_flags{};
        if (populated_on_target) {
            put_flags = MDBX_put_flags_t::MDBX_UPSERT;
        } else if (src_table_info.flags & MDBX_DUPSORT) {
            put_flags = MDBX_put_flags_t::MDBX_APPENDDUP;
        } else {
            put_flags = MDBX_put_flags_t::MDBX_APPEND;
        }

        auto data{src_table_crs.to_first(/*throw_notfound =*/false)};
        while (data) {
            ::mdbx::error::success_or_throw(tgt_table_crs.put(data.key, &data.value, put_flags));
            bytes_written += (data.key.length() + data.value.length());
            if (bytes_written >= 2_Gibi) {
                tgt_txn.commit();
                tgt_txn = tgt_env.start_write();
                tgt_table_crs.renew(tgt_txn);
                batch_committed = true;
                bytes_written = 0;
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
        bytes_written = 0;

        progress.set_current(src_table.stat.ms_entries);
        std::cout << progress.print_interval(batch_committed ? 'W' : '.') << std::flush;
    }

    std::cout << "\n All done!\n";
}

static size_t print_multi_table_diff(ROCursorDupSort* cursor1, ROCursorDupSort* cursor2, bool force_print = false) {
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

static size_t print_single_table_diff(ROCursor* cursor1, ROCursor* cursor2, bool force_print) {
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

static void print_table_diff(ROTxn& txn1, ROTxn& txn2, const DbTableInfo& table1, const DbTableInfo& table2, bool force_print = false) {
    ensure(table1.name == table2.name, [&]() { return "name mismatch: " + table1.name + " vs " + table2.name; });
    ensure(table1.info.key_mode() == table2.info.key_mode(),
           [&]() { return "key_mode mismatch: " + std::to_string(static_cast<int>(table1.info.key_mode())) + " vs " + std::to_string(static_cast<int>(table2.info.key_mode())); });
    ensure(table1.info.value_mode() == table2.info.value_mode(),
           [&]() { return "value_mode mismatch: " + std::to_string(static_cast<int>(table1.info.value_mode())) + " vs " + std::to_string(static_cast<int>(table2.info.value_mode())); });

    MapConfig table1_config{
        .name = table1.name.c_str(),
        .key_mode = table1.info.key_mode(),
        .value_mode = table1.info.value_mode(),
    };
    MapConfig table2_config{
        .name = table2.name.c_str(),
        .key_mode = table2.info.key_mode(),
        .value_mode = table2.info.value_mode(),
    };

    if (table1.stat.ms_entries == 0 && table2.stat.ms_entries == 0) {
        std::cout << "Both tables ( " << table1.name << ", " << table2.name << ") have zero entries, skipping deep check"
                  << "\n";
        return;
    }

    if (constexpr std::array kIrrelevantTables = {
            "FREE_DBI"sv,
            "MAIN_DBI"sv,
            "DbInfo"sv,
        };
        std::any_of(kIrrelevantTables.begin(), kIrrelevantTables.end(), [&table1](const std::string_view table_name) { return table_name == table1.name; })) {
        std::cout << "Skipping irrelevant table: " << table1.name << "\n";
        return;
    }

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
        SILK_WARN << "unsupported value mode: " << magic_enum::enum_name(table1_config.value_mode);
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

static DbComparisonResult compare_table_content(ROTxn& txn1, ROTxn& txn2, const DbTableInfo& db1_table, const DbTableInfo& db2_table,
                                                bool check_layout, bool deep, bool verbose) {
    // Check both databases have the same stats (e.g. number of records) for the specified table
    if (const auto result{compare(db1_table, db2_table, check_layout)}; !result || deep) {
        if (!result) {
            const std::string error_message{"mismatch in table " + db1_table.name + ": " + result.error()};
            if (verbose) {
                std::cerr << error_message << "\n";
            }
            print_table_diff(txn1, txn2, db1_table, db2_table);
            return tl::make_unexpected(error_message);
        }
        print_table_diff(txn1, txn2, db1_table, db2_table);
    }

    return {};
}

static DbComparisonResult compare_db_content(ROTxn& txn1, ROTxn& txn2, const DbInfo& db1_info, const DbInfo& db2_info,
                                             bool check_layout, bool deep, bool verbose) {
    const auto& db1_tables{db1_info.tables};
    const auto& db2_tables{db2_info.tables};
    SILKWORM_ASSERT(db1_tables.size() == db2_tables.size());

    // Check both databases have the same content for each table
    for (size_t i{0}; i < db1_tables.size(); ++i) {
        if (auto result{compare_table_content(txn1, txn2, db1_tables[i], db2_tables[i], check_layout, deep, verbose)}; !result) {
            return result;
        }
    }

    return {};
}

void compare(EnvConfig& config, const fs::path& target_datadir_path, bool check_layout, bool verbose, bool deep, std::optional<std::string_view> table) {
    ensure(fs::exists(target_datadir_path), [&]() { return "target datadir " + target_datadir_path.string() + " does not exist"; });
    ensure(fs::is_directory(target_datadir_path), [&]() { return "target datadir " + target_datadir_path.string() + " must be a folder"; });

    DataDirectory target_datadir{target_datadir_path};
    EnvConfig target_config{target_datadir.chaindata().path()};

    auto source_env{open_env(config)};
    ROTxnManaged source_txn{source_env};
    const auto source_db_info{get_tables_info(source_txn)};

    auto target_env{open_env(target_config)};
    ROTxnManaged target_txn{target_env};
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
        if (const auto result{compare_table_content(source_txn, target_txn, *db1_table, *db2_table, check_layout, deep, verbose)}; !result) {
            throw std::runtime_error{result.error()};
        }
    } else {
        // Check both databases have the same tables
        if (const auto result{compare_db_schema(source_db_info, target_db_info)}; !result) {
            throw std::runtime_error{result.error()};
        }

        // Check both databases have the same content in each table
        if (const auto result{compare_db_content(source_txn, target_txn, source_db_info, target_db_info, check_layout, deep, verbose)}; !result) {
            throw std::runtime_error{result.error()};
        }
    }
}

/**
 * \brief Initializes a silkworm db.
 *
 * Can parse a custom genesis file in json format or import data from known chain configs
 *
 * \param data_dir : hold data directory info about db paths
 * \param json_file : a string representing the path where to load custom json from
 * \param chain_id : an identifier for a known chain
 * \param dry : whether to commit data or run in simulation
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
    EnvConfig config{data_dir.chaindata().path().string(), /*create*/ true};
    auto env{open_env(config)};
    RWTxnManaged txn{env};
    table::check_or_create_chaindata_tables(txn);
    initialize_genesis(txn, genesis_json, /*allow_exceptions=*/true);

    // Set schema version
    VersionBase v{3, 0, 0};
    write_schema_version(txn, v);

    if (!dry) {
        txn.commit_and_renew();
    } else {
        txn.abort();
    }
    env.close();
}

void do_chainconfig(EnvConfig& config) {
    auto env{open_env(config)};
    ROTxnManaged txn{env};
    auto chain_config{read_chain_config(txn)};
    if (!chain_config.has_value()) {
        throw std::runtime_error("Not an initialized Silkworm db or unknown/custom chain ");
    }
    const auto& chain{chain_config.value()};
    std::cout << "\n Chain ID: " << chain.chain_id
              << "\n Settings (json): \n"
              << chain.to_json().dump(/*indent=*/2) << "\n\n";
}

void print_canonical_blocks(EnvConfig& config, BlockNum from, std::optional<BlockNum> to, uint64_t step) {
    auto env{open_env(config)};
    ROTxnManaged txn{env};

    // Determine last canonical block number
    auto canonical_hashes_table{txn.ro_cursor(table::kCanonicalHashes)};
    auto last_data{canonical_hashes_table->to_last(/*throw_notfound=*/false)};
    ensure(last_data.done, "Table CanonicalHashes is empty");
    ensure(last_data.key.size() == sizeof(BlockNum), "Table CanonicalHashes has unexpected key size");

    // Use last block as max block if to is missing and perform range checks
    BlockNum last{block_num_from_key(last_data.key)};
    if (to) {
        ensure(from <= *to, [&]() { return "Block from=" + std::to_string(from) + " must not be greater than to=" + std::to_string(*to); });
        ensure(*to <= last, [&]() { return "Block to=" + std::to_string(*to) + " must not be greater than last=" + std::to_string(last); });
    } else {
        ensure(from <= last, [&]() { return "Block from=" + std::to_string(from) + " must not be greater than last=" + std::to_string(last); });
        to = last;
    }

    // Read the range of block headers and bodies from database
    auto block_headers_table{txn.ro_cursor(table::kHeaders)};
    auto block_bodies_table{txn.ro_cursor(table::kBlockBodies)};
    for (BlockNum block_num{from}; block_num <= *to; block_num += step) {
        // Lookup each canonical block hash from each block number
        auto block_num_key{block_key(block_num)};
        auto ch_data{canonical_hashes_table->find(to_slice(block_num_key), /*throw_notfound=*/false)};
        ensure(ch_data.done, [&]() { return "Table CanonicalHashes does not contain key=" + to_hex(block_num_key); });
        const auto block_hash{to_bytes32(from_slice(ch_data.value))};

        // Read and decode each canonical block header
        auto block_key{db::block_key(block_num, block_hash.bytes)};
        auto bh_data{block_headers_table->find(to_slice(block_key), /*throw_notfound=*/false)};
        ensure(bh_data.done, [&]() { return "Table Headers does not contain key=" + to_hex(block_key); });
        ByteView block_header_data{from_slice(bh_data.value)};
        BlockHeader header;
        const auto res{rlp::decode(block_header_data, header)};
        ensure(res.has_value(), [&]() { return "Cannot decode block header from rlp=" + to_hex(from_slice(bh_data.value)); });

        // Read and decode each canonical block body
        auto bb_data{block_bodies_table->find(to_slice(block_key), /*throw_notfound=*/false)};
        if (!bb_data.done) {
            break;
        }
        ByteView block_body_data{from_slice(bb_data.value)};
        const auto stored_body{unwrap_or_throw(decode_stored_block_body(block_body_data))};

        // Print block information to console
        std::cout << "\nBlock number=" << block_num << "\n\n";
        print_header(header);
        std::cout << "\n";
        print_body(stored_body);
        std::cout << "\n\n";
    }
}

void print_blocks(EnvConfig& config, BlockNum from, std::optional<BlockNum> to, uint64_t step) {
    auto env{open_env(config)};
    ROTxnManaged txn{env};

    // Determine last block header number
    auto block_headers_table{txn.ro_cursor(table::kHeaders)};
    auto last_data{block_headers_table->to_last(/*throw_notfound=*/false)};
    ensure(last_data.done, "Table Headers is empty");
    ensure(last_data.key.size() == sizeof(BlockNum) + kHashLength, "Table Headers has unexpected key size");

    // Use last block as max block if to is missing and perform range checks
    BlockNum last{block_num_from_key(last_data.key)};
    if (to) {
        ensure(from <= *to, [&]() { return "Block from=" + std::to_string(from) + " must not be greater than to=" + std::to_string(*to); });
        ensure(*to <= last, [&]() { return "Block to=" + std::to_string(*to) + " must not be greater than last=" + std::to_string(last); });
    } else {
        ensure(from <= last, [&]() { return "Block from=" + std::to_string(from) + " must not be greater than last=" + std::to_string(last); });
        to = last;
    }

    // Read the range of block headers and bodies from database
    auto block_bodies_table{txn.ro_cursor(table::kBlockBodies)};
    for (BlockNum block_num{from}; block_num <= *to; block_num += step) {
        // Read and decode each block header
        auto block_key{db::block_key(block_num)};
        auto bh_data{block_headers_table->lower_bound(to_slice(block_key), /*throw_notfound=*/false)};
        ensure(bh_data.done, [&]() { return "Table Headers does not contain key=" + to_hex(block_key); });
        ByteView block_header_data{from_slice(bh_data.value)};
        BlockHeader header;
        const auto res{rlp::decode(block_header_data, header)};
        ensure(res.has_value(), [&]() { return "Cannot decode block header from rlp=" + to_hex(from_slice(bh_data.value)); });

        // Read and decode each block body
        auto bb_data{block_bodies_table->lower_bound(to_slice(block_key), /*throw_notfound=*/false)};
        if (!bb_data.done) {
            break;
        }
        ByteView block_body_data{from_slice(bb_data.value)};
        const auto stored_body{unwrap_or_throw(decode_stored_block_body(block_body_data))};

        // Print block information to console
        std::cout << "\nBlock number=" << block_num << "\n\n";
        print_header(header);
        std::cout << "\n";
        print_body(stored_body);
        std::cout << "\n\n";
    }
}

void do_first_byte_analysis(EnvConfig& config) {
    static std::string fmt_hdr{" %-24s %=50s "};

    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{open_env(config)};
    ROTxnManaged txn{env};

    std::cout << "\n"
              << (boost::format(fmt_hdr) % "Table name" % "%") << "\n"
              << (boost::format(fmt_hdr) % std::string(24, '-') % std::string(50, '-')) << "\n"
              << (boost::format(" %-24s ") % table::kCode.name) << std::flush;

    std::unordered_map<uint8_t, size_t> histogram;
    auto code_cursor{open_cursor(txn, table::kCode)};

    Progress progress{50};
    size_t total_entries{txn->get_map_stat(code_cursor.map()).ms_entries};
    progress.set_task_count(total_entries);
    size_t batch_size{progress.get_increment_count()};

    code_cursor.to_first();
    cursor_for_each(code_cursor,
                    [&histogram, &batch_size, &progress](ByteView, ByteView value) {
                        if (!value.empty()) {
                            uint8_t first_byte{value.at(0)};
                            ++histogram[first_byte];
                        }
                        if (!--batch_size) {
                            progress.set_current(progress.get_current() + progress.get_increment_count());
                            std::cout << progress.print_interval('.') << std::flush;
                            batch_size = progress.get_increment_count();
                        }
                    });

    BlockNum last_block{stages::read_stage_progress(txn, stages::kExecutionKey)};
    progress.set_current(total_entries);
    std::cout << progress.print_interval('.') << "\n";

    std::cout << "\n Last block : " << last_block << "\n Contracts  : " << total_entries << "\n\n";

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
                  << (boost::format(" %-4s %8s") % std::string(4, '-') % std::string(8, '-')) << "\n";
        for (const auto& [byte_code, usage_count] : histogram_sorted) {
            std::cout << (boost::format(" 0x%02x %8u") % static_cast<int>(byte_code) % usage_count) << "\n";
        }
    }

    std::cout << "\n\n";
}

void do_extract_headers(EnvConfig& config, const std::string& file_name, uint32_t step) {
    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{open_env(config)};
    ROTxnManaged txn{env};

    // We can store all header hashes into a single byte array given all hashes have same length.
    // We only need to ensure that the total size of the byte array is a multiple of hash length.
    // The process is mostly the same we have in genesistool.cpp

    // Open the output file
    std::ofstream out_stream{file_name};
    out_stream << "/* Generated by Silkworm toolbox's extract headers */\n"
               << "#include <cstdint>\n"
               << "#include <cstddef>\n"
               << "static const uint64_t kPreverifiedHashesMainnetInternal[] = {\n";

    BlockNum block_max{stages::read_stage_progress(txn, stages::kHeadersKey)};
    BlockNum max_block_num{0};
    auto hashes_table{open_cursor(txn, table::kCanonicalHashes)};

    for (BlockNum block_num = 0; block_num <= block_max; block_num += step) {
        auto block_key{db::block_key(block_num)};
        auto data{hashes_table.find(to_slice(block_key), false)};
        if (!data.done) {
            break;
        }

        const uint64_t* chuncks{reinterpret_cast<const uint64_t*>(from_slice(data.value).data())};
        out_stream << "   ";
        for (int i = 0; i < 4; ++i) {
            std::string hex{to_hex(chuncks[i], true)};
            out_stream << hex << ",";
        }
        out_stream << "\n";
        max_block_num = block_num;
    }

    out_stream
        << "};\n"
        << "const uint64_t* preverified_hashes_mainnet_data(){return &kPreverifiedHashesMainnetInternal[0];}\n"
        << "size_t sizeof_preverified_hashes_mainnet_data(){return sizeof(kPreverifiedHashesMainnetInternal);}\n"
        << "uint64_t preverified_hashes_mainnet_block_num(){return " << max_block_num << "ull;}\n\n";
    out_stream.close();
}

void do_freeze(EnvConfig& config, const DataDirectory& data_dir, bool keep_blocks) {
    using namespace concurrency::awaitable_wait_for_one;

    class StageSchedulerAdapter : public datastore::StageScheduler, public ActiveComponent {
      public:
        explicit StageSchedulerAdapter(RWAccess db_access)
            : db_access_(std::move(db_access)) {}
        ~StageSchedulerAdapter() override = default;

        void execution_loop() override {
            auto work_guard = boost::asio::make_work_guard(ioc_.get_executor());
            ioc_.run();
        }

        bool stop() override {
            ioc_.stop();
            return ActiveComponent::stop();
        }

        Task<void> schedule(std::function<void(RWTxn&)> callback) override {
            co_await concurrency::spawn_task(ioc_, [this, c = std::move(callback)]() -> Task<void> {
                auto tx = this->db_access_.start_rw_tx();
                c(tx);
                tx.commit_and_stop();
                co_return;
            });
        }

      private:
        boost::asio::io_context ioc_;
        RWAccess db_access_;
    };

    DataStore data_store{
        config,
        data_dir.snapshots().path(),
    };
    StageSchedulerAdapter stage_scheduler{data_store.chaindata().access_rw()};

    Freezer freezer{
        data_store.chaindata().access_ro(),
        data_store.ref().blocks_repository,
        stage_scheduler,
        data_dir.temp().path(),
        keep_blocks,
    };

    test_util::TaskRunner runner;
    runner.run(freezer.exec() || stage_scheduler.async_run("StageSchedulerAdapter"));
    stage_scheduler.stop();
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

    cmd::common::add_logging_options(app_main, log_settings);

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
    auto cmd_schema_force_version_update_opt = cmd_schema->add_flag("--force_version_update",
                                                                    "Force schema version update as required by current Silkworm code. "
                                                                    "Please be aware that this may corrupt or make your database unreadable. "
                                                                    "Do at your own risk.");

    // List migration keys
    auto cmd_migrations = app_main.add_subcommand("migrations", "List migrations");

    // Get value of table row by provided hex key or computed block key
    auto cmd_table_get = app_main.add_subcommand("table_get", "Get value provided the named table and the key");
    auto cmd_table_get_table_opt =
        cmd_table_get->add_option("--table", "Name of the table to read value from")
            ->required();
    auto cmd_table_get_key_opt =
        cmd_table_get->add_option("--key", "The key to lookup as hex string")
            ->check([&](const std::string& value) -> std::string {
                const auto hex = silkworm::from_hex(value);
                if (!hex) return "Value " + value + " is not a valid hex string";
                return {};
            });
    auto cmd_table_get_block_opt =
        cmd_table_get->add_option("--block", "Block number to compute the block key")
            ->check(CLI::Range(0u, UINT32_MAX))
            ->excludes(cmd_table_get_key_opt);

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
    auto cmd_compare_check_layout = cmd_compare->add_flag("--check_layout", "Check if B-tree structures match");
    auto cmd_compare_deep = cmd_compare->add_flag("--deep", "Run a deep comparison between two databases or tables by comparing keys and values");
    std::optional<std::string> cmd_compare_table;
    cmd_compare->add_option("--table", cmd_compare_table, "Name of specific table to compare")
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
    auto cmd_canonical_blocks_from = cmd_canonical_blocks->add_option("--from", "Block number to start with")
                                         ->required()
                                         ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_canonical_blocks_to = cmd_canonical_blocks->add_option("--to", "Block number to end with")
                                       ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_canonical_blocks_step = cmd_canonical_blocks->add_option("--step", "Step every this number of blocks")
                                         ->default_val("1")
                                         ->check(CLI::Range(1u, UINT32_MAX));

    // Print the list of saved blocks in specified range
    auto cmd_blocks = app_main.add_subcommand("blocks", "Print blocks from database in specified range");
    auto cmd_blocks_from = cmd_blocks->add_option("--from", "Block number to start with")
                               ->required()
                               ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_blocks_to = cmd_blocks->add_option("--to", "Block number to end with")
                             ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_blocks_step = cmd_blocks->add_option("--step", "Step every this number of blocks")
                               ->default_val("1")
                               ->check(CLI::Range(1u, UINT32_MAX));

    // Do first byte analytics on deployed contract codes
    auto cmd_first_byte_analysis = app_main.add_subcommand(
        "first-byte-analysis", "Prints an histogram analysis of first byte for deployed contracts");

    // Extract a list of historical headers in given file
    auto cmd_extract_headers = app_main.add_subcommand(
        "extract-headers", "Hard-code historical headers, from block zero to the max available");
    auto cmd_extract_headers_file_opt = cmd_extract_headers->add_option("--file", "Output file")->required();
    auto cmd_extract_headers_step_opt = cmd_extract_headers->add_option("--step", "Step every this number of blocks")
                                            ->default_val("100000")
                                            ->check(CLI::Range(1u, UINT32_MAX));

    // Freeze command
    auto cmd_freeze = app_main.add_subcommand("freeze", "Migrate data to snapshots");

    auto cmd_freeze_keep_blocks_opt = cmd_freeze->add_flag("--snap.keepblocks", "If set, the blocks exported from mdbx to snapshots are kept in mdbx");

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
        log::init(log_settings);

        // Set origin data_dir
        DataDirectory data_dir{data_dir_factory()};

        if (!*cmd_initgenesis) {
            if (!data_dir.chaindata().exists() || data_dir.chaindata().is_empty()) {
                std::cerr << "\n Directory " << data_dir.chaindata().path().string() << " does not exist or is empty\n";
                return -1;
            }
            auto mdbx_path{get_datafile_path(data_dir.chaindata().path())};
            if (!fs::exists(mdbx_path) || !fs::is_regular_file(mdbx_path)) {
                std::cerr << "\n Directory " << data_dir.chaindata().path().string() << " does not contain "
                          << kDbDataFileName << "\n";
                return -1;
            }
        }

        EnvConfig src_config{data_dir.chaindata().path().string()};
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
            do_schema(src_config, static_cast<bool>(*cmd_schema_force_version_update_opt));
        } else if (*cmd_migrations) {
            do_migrations(src_config);
        } else if (*cmd_table_get) {
            table_get(src_config,
                      cmd_table_get_table_opt->as<std::string>(),
                      *cmd_table_get_key_opt ? from_hex(cmd_table_get_key_opt->as<std::string>()) : std::nullopt,
                      *cmd_table_get_block_opt ? cmd_table_get_block_opt->as<std::optional<BlockNum>>() : std::nullopt);
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
            compare(src_config, cmd_compare_datadir->as<std::filesystem::path>(), cmd_compare_check_layout->as<bool>(),
                    cmd_compare_verbose->as<bool>(), cmd_compare_deep->as<bool>(), cmd_compare_table);
        } else if (*cmd_initgenesis) {
            do_init_genesis(data_dir, cmd_initgenesis_json_opt->as<std::string>(),
                            *cmd_initgenesis_chain_opt ? cmd_initgenesis_chain_opt->as<uint32_t>() : 0u,
                            static_cast<bool>(*app_dry_opt));
            if (*app_dry_opt) {
                std::cout << "\nGenesis initialization succeeded. Due to --dry flag no data is persisted\n\n";
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
        } else if (*cmd_freeze) {
            do_freeze(src_config, data_dir, static_cast<bool>(*cmd_freeze_keep_blocks_opt));
        }

        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "\nError: " << ex.what() << "\n\n";
    } catch (...) {
        std::cerr << "\nUnexpected undefined error\n\n";
    }

    return -1;
}
