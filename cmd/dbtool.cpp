/*
   Copyright 2020-2021 The Silkworm Authors

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

#include <csignal>
#include <filesystem>
#include <iostream>
#include <regex>
#include <string>

#include <CLI/CLI.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <magic_enum.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/types/block.hpp>

namespace fs = std::filesystem;
using namespace silkworm;

bool shouldStop{false};

class Progress {
  public:
    Progress(uint32_t width) : bar_width_{width}, percent_step_{100u / width} {};
    ~Progress() = default;

    // Return current percentage
    uint32_t percent(void) {
        if (!max_counter_) return 100;
        if (!current_counter_) return 0;
        return static_cast<uint32_t>(current_counter_ * 100 / max_counter_);
    }

    void step(void) { current_counter_++; }
    void set_current(size_t count) { current_counter_ = std::max(count, current_counter_); }
    size_t get_current(void) { return current_counter_; }

    size_t get_increment_count(void) { return (max_counter_ / bar_width_); }

    // Resets everything to zero
    void reset() {
        current_counter_ = 0;
        printed_bar_len_ = 0;
    }
    void set_task_count(size_t iterations) {
        reset();
        max_counter_ = iterations;
    }

    // Prints progress ticks
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

    std::string print_progress(char c = '.') {
        uint32_t percentage{percent()};
        uint32_t numChars{percentage / percent_step_};
        if (!numChars) return "";
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

struct dbTableEntry {
    MDBX_dbi id{0};
    std::string name{};
    mdbx::txn::map_stat stat;
    mdbx::map_handle::info info;
    size_t pages(void) { return stat.ms_branch_pages + stat.ms_leaf_pages + stat.ms_overflow_pages; }
    size_t size(void) { return pages() * stat.ms_psize; }
};

struct dbTablesInfo {
    size_t mapsize{0};
    size_t filesize{0};
    size_t pageSize{0};
    size_t pages{0};
    size_t size{0};
    std::vector<dbTableEntry> tables{};
};

struct dbFreeEntry {
    size_t id{0};
    size_t pages{0};
    size_t size{0};
};

struct dbFreeInfo {
    size_t pages{0};
    size_t size{0};
    std::vector<dbFreeEntry> entries{};
};

struct DbOptions {
    std::string datadir{DataDirectory{}.get_chaindata_path().string()};  // Where data file is located
    bool shared{false};                                                  // Whether db has to be opened in shared mode
};

struct StageSetOptions {
    std::string name{};  // Name of the stage to set;
    uint32_t height{0};  // New height to set
};

void sig_handler(int signum) {
    (void)signum;
    std::cout << "\n Request for termination intercepted. Stopping ..." << std::endl;
    shouldStop = true;
}

void do_clear(db::EnvConfig& config, bool dry, bool always_yes, std::vector<std::string> table_names, bool drop) {
    config.readonly = false;
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
            std::regex pattern{"^([yY])?([nN])?$"};
            std::smatch matches;

            std::string user_input;
            std::cout << "Confirm ? [y/N] ";
            do {
                std::cin >> user_input;
                std::cin.clear();
                if (std::regex_search(user_input, matches, pattern, std::regex_constants::match_default)) {
                    break;
                };
            } while (true);

            if (matches[2].length()) {
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

dbFreeInfo get_freeInfo(::mdbx::txn& txn) {
    dbFreeInfo ret{};

    ::mdbx::map_handle free_map{0};
    auto free_stat{txn.get_map_stat(free_map)};
    auto free_crs{txn.open_cursor(free_map)};

    const auto& collect_func{[&ret, &free_stat](::mdbx::cursor::move_result data) -> bool {
        size_t txId = *(static_cast<size_t*>(data.key.iov_base));
        size_t pagesCount = *(static_cast<uint32_t*>(data.value.iov_base));
        size_t pagesSize = pagesCount * free_stat.ms_psize;
        ret.pages += pagesCount;
        ret.size += pagesSize;
        ret.entries.push_back({txId, pagesCount, pagesSize});
        return true;
    }};

    if (free_crs.to_first(/*throw_notfound =*/false)) {
        (void)db::for_each(free_crs, collect_func);
    }

    return ret;
}

dbTablesInfo get_tablesInfo(::mdbx::txn& txn) {
    dbTablesInfo ret{};
    dbTableEntry* table;

    ret.filesize = txn.env().get_info().mi_geo.current;

    // Get info from the free database
    ::mdbx::map_handle free_map{0};
    auto stat = txn.get_map_stat(free_map);
    auto info = txn.get_handle_info(free_map);
    table = new dbTableEntry{free_map.dbi, "FREE_DBI", stat, info};
    ret.pageSize += table->stat.ms_psize;
    ret.pages += table->pages();
    ret.size += table->size();
    ret.tables.push_back(*table);

    // Get info from the unnamed database
    ::mdbx::map_handle main_map{1};
    stat = txn.get_map_stat(main_map);
    info = txn.get_handle_info(main_map);
    table = new dbTableEntry{main_map.dbi, "MAIN_DBI", stat, info};
    ret.pageSize += table->stat.ms_psize;
    ret.pages += table->pages();
    ret.size += table->size();
    ret.tables.push_back(*table);

    // Get all tables from the unnamed database
    auto main_crs{txn.open_cursor(main_map)};
    auto result{main_crs.to_first(/*throw_notfound =*/false)};
    while (result) {
        auto named_map{txn.open_map(result.key.as_string())};
        stat = txn.get_map_stat(named_map);
        info = txn.get_handle_info(named_map);
        table = new dbTableEntry{named_map.dbi, result.key.as_string(), stat, info};

        ret.pageSize += table->stat.ms_psize;
        ret.pages += table->pages();
        ret.size += table->size();
        ret.tables.push_back(*table);
        result = main_crs.to_next(/*throw_notfound =*/false);
    }

    return ret;
}

void do_scan(db::EnvConfig config) {
    static std::string fmt_hdr{" %3s %-24s %=50s %13s %13s %13s"};

    auto env{silkworm::db::open_env(config)};
    auto txn{env.start_read()};

    auto tablesInfo{get_tablesInfo(txn)};

    std::cout << "\n Database tables    : " << tablesInfo.tables.size() << "\n" << std::endl;

    if (tablesInfo.tables.size()) {
        std::cout << (boost::format(fmt_hdr) % "Dbi" % "Table name" % "Progress" % "Keys" % "Data" % "Total")
                  << std::endl;
        std::cout << (boost::format(fmt_hdr) % std::string(3, '-') % std::string(24, '-') % std::string(50, '-') %
                      std::string(13, '-') % std::string(13, '-') % std::string(13, '-'))
                  << std::flush;

        for (dbTableEntry item : tablesInfo.tables) {
            mdbx::map_handle tbl_map;

            std::cout << "\n" << (boost::format(" %3u %-24s ") % item.id % item.name) << std::flush;

            if (item.id < 2) {
                tbl_map = mdbx::map_handle(item.id);
            } else {
                tbl_map = txn.open_map(item.name);
            };

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
                    if (shouldStop) {
                        break;
                    }
                    progress.set_current(progress.get_current() + progress.get_increment_count());
                    std::cout << progress.print_interval('.') << std::flush;
                    batch_size = progress.get_increment_count();
                }
                result = tbl_crs.to_next(/*throw_notfound =*/false);
            }

            if (!shouldStop) {
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

    std::cout << "\n" << (shouldStop ? "Aborted" : "Done") << " !\n " << std::endl;
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
        std::cout << "\n" << (boost::format(fmt_hdr) % "Stage Name" % "Block") << std::endl;
        std::cout << (boost::format(fmt_hdr) % std::string(24, '-') % std::string(10, '-')) << std::endl;

        auto result{crs.to_first(/*throw_notfound =*/false)};
        while (result) {
            size_t height{endian::load_big_u64(static_cast<uint8_t*>(result.value.iov_base))};
            bool Known{db::stages::is_known_stage(result.key.char_ptr())};
            std::cout << (boost::format(fmt_row) % result.key.as_string() % height %
                          (Known ? std::string(8, ' ') : "Unknown"))
                      << std::endl;
            result = crs.to_next(/*throw_notfound =*/false);
        }
        std::cout << "\n" << std::endl;
    } else {
        std::cout << "\n There are no stages to list\n" << std::endl;
    }
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
        std::cout << "\n" << (boost::format(fmt_hdr) % "Migration Name") << std::endl;
        std::cout << (boost::format(fmt_hdr) % std::string(24, '-')) << std::endl;

        auto result{crs.to_first(/*throw_notfound =*/false)};
        while (result) {
            std::cout << (boost::format(fmt_row) % result.key.as_string()) << std::endl;
            result = crs.to_next(/*throw_notfound =*/false);
        }
        std::cout << "\n" << std::endl;
    } else {
        std::cout << "\n There are no migrations to list\n" << std::endl;
    }
}

int do_stage_set(DbOptions& db_opts, StageSetOptions set_opts) {
    int retvar{0};
    try {
        db::EnvConfig config{db_opts.datadir};
        config.readonly = false;
        config.shared = db_opts.shared;
        auto env{silkworm::db::open_env(config)};
        auto txn{env.start_write()};

        auto old_height{db::stages::get_stage_progress(txn, set_opts.name.c_str())};
        db::stages::set_stage_progress(txn, set_opts.name.c_str(), set_opts.height);
        txn.commit();

        std::cout << "Stage " << set_opts.name << " touched from " << old_height << " to " << set_opts.height
                  << std::endl;

    } catch (const std::exception& ex) {
        retvar = -1;
        std::cout << ex.what() << std::endl;
    }
    return retvar;
}

void do_tables(db::EnvConfig& config) {
    static std::string fmt_hdr{" %3s %-24s %10s %2s %10s %10s %10s %12s %10s %10s"};
    static std::string fmt_row{" %3i %-24s %10u %2u %10u %10u %10u %12s %10s %10s"};

    auto env{silkworm::db::open_env(config)};
    auto txn{env.start_read()};

    auto tables{get_tablesInfo(txn)};
    auto freeInfo{get_freeInfo(txn)};

    std::cout << "\n Database tables    : " << tables.tables.size() << "\n" << std::endl;

    if (tables.tables.size()) {
        std::cout << (boost::format(fmt_hdr) % "Dbi" % "Table name" % "Records" % "D" % "Branch" % "Leaf" % "Overflow" %
                      "Size" % "Key" % "Value")
                  << std::endl;
        std::cout << (boost::format(fmt_hdr) % std::string(3, '-') % std::string(24, '-') % std::string(10, '-') %
                      std::string(2, '-') % std::string(10, '-') % std::string(10, '-') % std::string(10, '-') %
                      std::string(12, '-') % std::string(10, '-') % std::string(10, '-'))
                  << std::endl;

        for (auto item : tables.tables) {
            auto keymode = magic_enum::enum_name(item.info.key_mode());
            auto valuemode = magic_enum::enum_name(item.info.value_mode());

            std::cout << (boost::format(fmt_row) % item.id % item.name % item.stat.ms_entries % item.stat.ms_depth %
                          item.stat.ms_branch_pages % item.stat.ms_leaf_pages % item.stat.ms_overflow_pages %
                          human_size(item.size()) % keymode % valuemode)
                      << std::endl;
        }
    }

    std::cout << "\n Database file size   (A) : " << (boost::format("%13s") % human_size(tables.filesize)) << std::endl;
    std::cout << " Data pages count         : " << (boost::format("%13u") % tables.pages) << std::endl;
    std::cout << " Data pages size      (B) : " << (boost::format("%13s") % human_size(tables.size)) << std::endl;
    std::cout << " Free pages count         : " << (boost::format("%13u") % tables.tables[0].pages()) << std::endl;
    std::cout << " Free pages size      (C) : " << (boost::format("%13s") % human_size(freeInfo.size)) << std::endl;
    std::cout << " Reclaimable space        : "
              << (boost::format("%13s") % human_size(tables.filesize - tables.size + freeInfo.size))
              << " == A - B + C \n"
              << std::endl;
}

void do_freelist(db::EnvConfig& config, bool detail) {
    static std::string fmt_hdr{"%9s %9s %12s"};
    static std::string fmt_row{"%9u %9u %12s"};

    auto env{silkworm::db::open_env(config)};
    auto txn{env.start_read()};

    auto freeInfo{get_freeInfo(txn)};

    if (freeInfo.entries.size() && detail) {
        std::cout << std::endl;
        std::cout << (boost::format(fmt_hdr) % "TxId" % "Pages" % "Size") << std::endl;
        std::cout << (boost::format(fmt_hdr) % std::string(9, '-') % std::string(9, '-') % std::string(12, '-'))
                  << std::endl;
        for (auto& item : freeInfo.entries) {
            std::cout << (boost::format(fmt_row) % item.id % item.pages % human_size(item.size)) << std::endl;
        }
    }
    std::cout << "\n Free pages count     : " << boost::format("%13u") % freeInfo.pages << "\n"
              << " Free pages size      : " << boost::format("%13s") % human_size(freeInfo.size) << "\n"
              << std::endl;
}

void do_schema(db::EnvConfig& config) {
    auto env{silkworm::db::open_env(config)};
    auto txn{env.start_read()};

    auto schema_version{db::read_schema_version(txn)};
    if (!schema_version.has_value()) {
        throw std::runtime_error("Not a Silkworm db or no schema version found");
    }
    std::cout << "\n"
              << "Database schema version : " << schema_version->to_string() << "\n"
              << std::endl;
}

void do_compact(db::EnvConfig& config, std::string work_dir, bool replace, bool nobak) {
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
    std::cout << "\n Database compaction " << (shouldStop ? "aborted !" : "completed ...") << std::endl;
    env.close();

    if (!shouldStop) {
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

int do_copy(db::EnvConfig& src_config, std::string& target_dir, bool create, bool noempty,
            std::vector<std::string>& names, std::vector<std::string>& xnames, bool dry) {
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
    auto src_tableInfo = get_tablesInfo(src_txn);
    auto tgt_tableInfo = get_tablesInfo(tgt_txn);

    // Check source db has tables to copy besides the two system tables
    if (src_tableInfo.tables.size() < 3) {
        throw std::runtime_error("Source db has no tables to copy.");
    }

    size_t bytesWritten{0};
    std::cout << boost::format(" %-24s %=50s") % "Table" % "Progress" << std::endl;
    std::cout << boost::format(" %-24s %=50s") % std::string(24, '-') % std::string(50, '-') << std::flush;

    // Loop source tables
    for (auto& src_table : src_tableInfo.tables) {
        if (shouldStop) {
            break;
        }
        std::cout << "\n " << boost::format("%-24s ") % src_table.name << std::flush;

        // Is this a system table ?
        if (src_table.id < 2) {
            std::cout << "Skipped (SYSTEM TABLE)" << std::flush;
            continue;
        }

        // Is this table present in the list user has provided ?
        if (names.size()) {
            auto it = std::find(names.begin(), names.end(), src_table.name);
            if (it == names.end()) {
                std::cout << "Skipped (no match --tables)" << std::flush;
                continue;
            }
        }

        // Is this table present in the list user has excluded ?
        if (xnames.size()) {
            auto it = std::find(xnames.begin(), xnames.end(), src_table.name);
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
        if (tgt_tableInfo.tables.size()) {
            auto it = std::find_if(tgt_tableInfo.tables.begin(), tgt_tableInfo.tables.end(),
                                   boost::bind(&dbTableEntry::name, _1) == src_table.name);
            if (it != tgt_tableInfo.tables.end()) {
                exists_on_target = true;
                populated_on_target = (it->stat.ms_entries > 0);
            }
        }

        // Ready to copy
        auto src_table_map{src_txn.open_map(src_table.name)};
        auto src_table_info{src_txn.get_handle_info(src_table_map)};

        // If table does not exist on target create it with same flags as
        // origin table. Otherwise check the info match
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
        MDBX_put_flags_t put_flags{!populated_on_target
                                       ? MDBX_put_flags_t::MDBX_UPSERT
                                       : ((src_table_info.flags & MDBX_DUPSORT) ? MDBX_put_flags_t::MDBX_APPENDDUP
                                                                                : MDBX_put_flags_t::MDBX_APPEND)};

        auto data{src_table_crs.to_first(/*throw_notfound =*/false)};
        while (data) {
            tgt_table_crs.put(data.key, &data.value, put_flags);
            bytesWritten += (data.key.length() + data.value.length());
            if (bytesWritten >= 2_Gibi) {
                tgt_table_crs.close();
                if (!dry) {
                    tgt_txn.commit();
                } else {
                    tgt_txn.abort();
                }
                tgt_txn = tgt_env.start_write();
                if (dry && !exists_on_target) {
                    tgt_table_map =
                        tgt_txn.create_map(src_table.name, src_table_info.key_mode(), src_table_info.value_mode());
                } else {
                    tgt_table_map = tgt_txn.open_map(src_table.name);
                }
                tgt_table_crs = tgt_txn.open_cursor(tgt_table_map);
                batch_committed = true;
                bytesWritten = 0;
            }

            if (!--batch_size) {
                if (shouldStop) {
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
        if (!shouldStop && bytesWritten) {
            if (!dry) {
                tgt_txn.commit();
            } else {
                tgt_txn.abort();
            }
            tgt_txn = tgt_env.start_write();
            batch_committed = true;
            bytesWritten = 0;
        }

        progress.set_current(src_table.stat.ms_entries);
        std::cout << progress.print_interval(batch_committed ? 'W' : '.') << std::flush;
    }

    std::cout << "\n All done!" << std::endl;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    StageSetOptions stage_set_opts{};  // Options for stage set

    CLI::App app_main("Silkworm db tool");
    app_main.require_subcommand(1);  // At least 1 subcommand is required

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
    auto cmd_copy = app_main.add_subcommand("copy", "Copies an entire Silkworm database or subset of tables");
    auto cmd_copy_targetdir_opt = cmd_copy->add_option("--targetdir", "Target directory")->required();
    auto cmd_copy_target_create_opt = cmd_copy->add_flag("--create", "Create target db if not exists");
    auto cmd_copy_target_noempty_opt = cmd_copy->add_flag("--noempty", "Skip copy of empty tables");
    std::vector<std::string> cmd_copy_names, cmd_copy_xnames;
    cmd_copy->add_option("--tables", cmd_copy_names, "Copy only tables matching this list of names", true);
    cmd_copy->add_option("--xtables", cmd_copy_xnames, "Don't copy tables matching this list of names", true);

    // Stages tool
    auto& app_stage_set = *app_main.add_subcommand("stageset", "Sets a stage to a new height");
    app_stage_set.add_option("--name", stage_set_opts.name, "Name of the stage to set", false)->required();
    app_stage_set.add_option("--height", stage_set_opts.height, "New height for stage", false)
        ->required()
        ->check(CLI::Range(0u, UINT32_MAX));

    /*
    * Parse arguments and validate
    */
    CLI11_PARSE(app_main, argc, argv);

    try {

        // Set origin data_dir
        DataDirectory data_dir;
        if (*chaindata_opt) {
            fs::path p{chaindata_opt->as<std::string>()};
            data_dir = DataDirectory::from_chaindata(p);
        } else {
            fs::path p{datadir_opt->as<std::string>()};
            data_dir = DataDirectory(p);
        }

        if (!fs::exists(data_dir.get_chaindata_path()) || !fs::is_directory(data_dir.get_chaindata_path()) ||
            fs::is_empty(data_dir.get_chaindata_path())) {
            std::cerr << "\n Directory " << data_dir.get_chaindata_path() << " does not exist or is empty" << std::endl;
            return -1;
        }
        auto mdbx_path{db::get_datafile_path(data_dir.get_chaindata_path())};
        if (!fs::exists(mdbx_path) || !fs::is_regular_file(mdbx_path)) {
            std::cerr << "\n Directory " << data_dir.get_chaindata_path() << " does not contain " << db::kDbDataFileName
                      << std::endl;
            return -1;
        }

        db::EnvConfig src_config{data_dir.get_chaindata_path().string()};
        src_config.shared = *shared_opt;
        src_config.exclusive = *exclusive_opt;
        src_config.readonly = true;

        // Execute subcommand actions
        if (*cmd_tables) {
            if (*cmd_tables_scan_opt) {
                do_scan(src_config);
            } else {
                do_tables(src_config);
            }
        } else if (*cmd_freelist) {
            do_freelist(src_config, *freelist_detail_opt);
        } else if (*cmd_schema) {
            do_schema(src_config);
        } else if (*cmd_stages) {
            do_stages(src_config);
        } else if (*cmd_migrations) {
            do_migrations(src_config);
        } else if (*cmd_clear) {
            do_clear(src_config, *app_dry_opt, *app_yes_opt, cmd_clear_names, *cmd_clear_drop_opt);
        } else if (*cmd_compact) {
            do_compact(src_config, cmd_compact_workdir_opt->as<std::string>(), *cmd_compact_replace_opt,
                       *cmd_compact_nobak_opt);
        } else if (*cmd_copy) {
            do_copy(src_config, cmd_copy_targetdir_opt->as<std::string>(), *cmd_copy_target_create_opt,
                    *cmd_copy_target_noempty_opt, cmd_copy_names, cmd_copy_xnames, *app_dry_opt);
        };

        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "\nUnexpected error : " << ex.what() << std::endl;
    } catch (...) {
        std::cerr << "\nUnexpected undefined error" << std::endl;
    }

    return -1;
}
