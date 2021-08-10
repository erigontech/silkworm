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
#include <boost/endian/conversion.hpp>
#include <boost/format.hpp>
#include <magic_enum.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/data_dir.hpp>
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

struct FreeListOptions {
    bool details{false};  // Wheter or not print detailed list
};

struct ClearOptions {
    std::vector<std::string> names{};  // Name of table(s) to clear
    bool drop{false};                  // Whether or not to drop table instead of clearing
    bool yes{false};                   // Assume yes to all requests of confirmation
};

struct CompactOptions {
    std::string workdir{};  // Where compacted file should be located
    bool replace{false};    // Wheter or not compacted file shoudl replace original one
    bool nobak{false};      // Whether or not the original file should be renamed to bak
    fs::path dir{};         // Path to target data directory (i.e. workdir)
    fs::path file{};        // Path to target data file
};

struct CopyOptions {
    std::string targetdir{};             // Target directory of database
    bool create{false};                  // Whether or not new data file have to be created
    bool noempty{false};                 // Omit copying a table when empty
    bool upsert{false};                  // Copy using upsert instead of append (reuses free pages if any)
    std::vector<std::string> tables{};   // A limited set of table names to copy
    std::vector<std::string> xtables{};  // A limited set of table names to NOT copy
    std::string commitsize_str{"1GB"};   // Provided commit size literal default 5GB
    uint64_t commitsize{0};              // Computed commit size
    fs::path dir{};                      // Path to target data directory (i.e. workdir)
    fs::path file{};                     // Path to target data file
    size_t filesize{0};                  // Size of target file if exists
};

struct StageSetOptions {
    std::string name{};  // Name of the stage to set;
    uint32_t height{0};  // New height to set
};

void sig_handler(int signum) {
    (void)signum;
    std::cout << std::endl << "Request for termination intercepted. Stopping ..." << std::endl << std::endl;
    shouldStop = true;
}

int do_clear(DbOptions& db_opts, ClearOptions& app_opts) {
    int retvar{0};

    try {
        db::EnvConfig config{db_opts.datadir};
        config.shared = db_opts.shared;
        auto env{db::open_env(config)};
        auto txn{env.start_write()};

        for (const auto& tablename : app_opts.names) {
            mdbx::map_handle table_map;
            try {
                table_map = txn.open_map(tablename);
            } catch (const std::exception&) {
                std::cout << "Table " << tablename << " not found" << std::endl;
                continue;
            }

            size_t rcount{txn.get_map_stat(table_map).ms_entries};

            if (!rcount && !app_opts.drop) {
                std::cout << " Table " << tablename << " is already empty. Skipping" << std::endl;
                continue;
            }

            std::cout << "\n"
                      << (app_opts.drop ? "Dropping" : "Emptying") << " table " << tablename << " (" << rcount
                      << " records) " << std::flush;

            if (!app_opts.yes) {
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

            if (app_opts.drop) {
                txn.drop_map(table_map);
            } else {
                txn.clear_map(table_map);
            }
        }

        std::cout << "Committing ... " << std::endl;
        txn.commit();

        std::cout << "Success !" << std::endl;

    } catch (std::logic_error& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    } catch (std::exception& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    return retvar;
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

int do_scan(DbOptions& db_opts) {
    static std::string fmt_hdr{" %3s %-24s %=50s %13s %13s %13s"};

    int retvar{0};

    try {
        db::EnvConfig config{db_opts.datadir};
        config.readonly = true;
        config.shared = db_opts.shared;
        auto env{silkworm::db::open_env(config)};
        auto txn{env.start_read()};

        auto tablesInfo{get_tablesInfo(txn)};

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
                        progress.set_current(progress.get_current() + progress.get_increment_count());
                        std::cout << progress.print_interval('.') << std::flush;
                        batch_size = progress.get_increment_count();
                        if (shouldStop) break;
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

        std::cout << "\n\nDone !" << std::endl;

    } catch (std::exception& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    return retvar;
}

int do_stages(DbOptions& db_opts) {
    static std::string fmt_hdr{" %-24s %10s "};
    static std::string fmt_row{" %-24s %10u %-8s"};

    int retvar{0};

    try {
        db::EnvConfig config{db_opts.datadir};
        config.readonly = true;
        config.shared = db_opts.shared;
        auto env{silkworm::db::open_env(config)};
        auto txn{env.start_read()};
        auto crs{db::open_cursor(txn, db::table::kSyncStageProgress)};

        if (txn.get_map_stat(crs.map()).ms_entries) {
            std::cout << "\n" << (boost::format(fmt_hdr) % "Stage Name" % "Block") << std::endl;
            std::cout << (boost::format(fmt_hdr) % std::string(24, '-') % std::string(10, '-')) << std::endl;

            auto result{crs.to_first(/*throw_notfound =*/false)};
            while (result) {
                size_t height{boost::endian::load_big_u64(static_cast<uint8_t*>(result.value.iov_base))};
                bool Known{db::stages::is_known_stage(result.key.char_ptr())};
                std::cout << (boost::format(fmt_row) % result.key.as_string() % height %
                              (Known ? std::string(8, ' ') : "Unknown"))
                          << std::endl;
                result = crs.to_next(/*throw_notfound =*/false);
            }
        } else {
            std::cout << "\n There are no stages to list" << std::endl;
        }

        std::cout << std::endl << std::endl;

    } catch (std::exception& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    return retvar;
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

int do_tables(DbOptions& db_opts) {
    static std::string fmt_hdr{" %3s %-24s %10s %2s %10s %10s %10s %12s %10s %10s"};
    static std::string fmt_row{" %3i %-24s %10u %2u %10u %10u %10u %12s %10s %10s"};

    int retvar{0};

    try {
        db::EnvConfig config{db_opts.datadir};
        config.readonly = true;
        config.shared = db_opts.shared;
        auto env{silkworm::db::open_env(config)};
        auto txn{env.start_read()};

        auto tables{get_tablesInfo(txn)};
        auto freeInfo{get_freeInfo(txn)};

        std::cout << "\n Database tables    : " << tables.tables.size() << std::endl << std::endl;

        if (tables.tables.size()) {
            std::cout << (boost::format(fmt_hdr) % "Dbi" % "Table name" % "Records" % "D" % "Branch" % "Leaf" %
                          "Overflow" % "Size" % "Key" % "Value")
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

        std::cout << "\n Database file size   (A) : " << (boost::format("%13s") % human_size(tables.filesize))
                  << std::endl;
        std::cout << " Data pages count         : " << (boost::format("%13u") % tables.pages) << std::endl;
        std::cout << " Data pages size      (B) : " << (boost::format("%13s") % human_size(tables.size)) << std::endl;
        std::cout << " Free pages count         : " << (boost::format("%13u") % tables.tables[0].pages()) << std::endl;
        std::cout << " Free pages size      (C) : " << (boost::format("%13s") % human_size(freeInfo.size)) << std::endl;
        std::cout << " Reclaimable space        : "
                  << (boost::format("%13s") % human_size(tables.filesize - tables.size + freeInfo.size))
                  << " == A - B + C \n"
                  << std::endl;

    } catch (const std::exception& ex) {
        retvar = -1;
        std::cout << ex.what() << std::endl;
    }

    return retvar;
}

int do_freelist(DbOptions& db_opts, FreeListOptions& app_opts) {
    static std::string fmt_hdr{"%9s %9s %12s"};
    static std::string fmt_row{"%9u %9u %12s"};

    int retvar{0};

    try {
        db::EnvConfig config{db_opts.datadir};
        config.readonly = true;
        config.shared = db_opts.shared;
        auto env{silkworm::db::open_env(config)};
        auto txn{env.start_read()};

        auto freeInfo{get_freeInfo(txn)};

        if (freeInfo.entries.size() && app_opts.details) {
            std::cout << std::endl;
            std::cout << (boost::format(fmt_hdr) % "TxId" % "Pages" % "Size") << std::endl;
            std::cout << (boost::format(fmt_hdr) % std::string(9, '-') % std::string(9, '-') % std::string(12, '-'))
                      << std::endl;
            for (auto& item : freeInfo.entries) {
                std::cout << (boost::format(fmt_row) % item.id % item.pages % human_size(item.size)) << std::endl;
            }
        }
        std::cout << "\n Free pages count     : " << boost::format("%13u") % freeInfo.pages << "\n"
                  << " Free pages size      : " << boost::format("%13s") % human_size(freeInfo.size) << std::endl;

    } catch (std::exception& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    return retvar;
}

int do_schema(DbOptions& db_opts) {
    int retvar{0};
    try {
        db::EnvConfig config{db_opts.datadir};
        config.readonly = true;
        config.shared = db_opts.shared;
        auto env{silkworm::db::open_env(config)};
        auto txn{env.start_read()};

        auto schema_version{db::read_schema_version(txn)};
        if (!schema_version.has_value()) {
            std::cout << "\n"
                      << "Either not an Erigon db or no schema version found"
                      << "\n"
                      << std::endl;
        } else {
            std::cout << "\n"
                      << "Erigon schema version " << schema_version->to_string() << "\n"
                      << std::endl;
        }
    } catch (std::exception& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    return retvar;
}

int do_compact(DbOptions& db_opts, CompactOptions& app_opts) {
    int retvar{0};

    try {
        db::EnvConfig config{db_opts.datadir};
        config.readonly = true;
        config.shared = db_opts.shared;
        auto env{silkworm::db::open_env(config)};

        size_t src_filesize{env.get_info().mi_geo.current};
        MDBX_env_flags_t src_flags{env.get_flags()};
        bool src_nosubdir{(src_flags & MDBX_NOSUBDIR) == MDBX_NOSUBDIR};

        fs::path src_path{db_opts.datadir};
        if (!src_nosubdir) src_path /= fs::path{db::kDbDataFileName};

        // Ensure target working directory has enough free space
        // at least the size of origin db
        auto tgt_path = fs::path{app_opts.workdir};
        if (!src_nosubdir) tgt_path /= fs::path{db::kDbDataFileName};
        auto target_space = fs::space(tgt_path.parent_path());
        if (target_space.free <= src_filesize) {
            throw std::runtime_error("Insufficient disk space on working directory");
        }

        std::cout << " Compacting " << src_path << "\n into " << tgt_path
                  << "\n Please be patient as there is no progress report ..." << std::endl;
        env.copy(/*destination*/ tgt_path.string(), /*compactify*/ true, /*forcedynamic*/ true);
        std::cout << "\n Database compaction " << (shouldStop ? "aborted !" : "completed ...") << std::endl;
        env.close();

        if (!shouldStop) {
            // Do we have a valid compacted file on disk ?
            // replace source with target
            if (!fs::exists(tgt_path)) {
                throw std::runtime_error("Can't locate compacted database");
            }

            // Do we have to replace original file ?
            if (app_opts.replace && !src_nosubdir) {
                // Create a backup copy before replacing ?
                if (!app_opts.nobak) {
                    std::cout << " Creating backup copy of origin database ..." << std::endl;
                    std::string src_file_back{db::kDbDataFileName};
                    src_file_back.append(".bak");
                    fs::path src_path_bak{src_path.parent_path() / fs::path{src_file_back}};
                    if (fs::exists(src_path_bak)) fs::remove(src_path_bak);
                    fs::rename(src_path, src_path_bak);
                }

                std::cout << " Replacing origin database with compacted ..." << std::endl;
                if (fs::exists(src_path)) fs::remove(src_path);
                fs::rename(src_path, tgt_path);
            }
        }

        std::cout << " All done !" << std::endl;

    } catch (const std::exception& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    return retvar;
}

int do_copy(DbOptions& db_opts, CopyOptions& app_opts) {
    int retvar{0};

    try {
        // Source db
        db::EnvConfig src_config{db_opts.datadir};
        src_config.readonly = true;
        src_config.shared = db_opts.shared;
        auto src_env{silkworm::db::open_env(src_config)};
        auto src_txn{src_env.start_read()};

        // Target db
        db::EnvConfig tgt_config{app_opts.targetdir};
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
            if (shouldStop) break;
            std::cout << "\n " << boost::format("%-24s ") % src_table.name << std::flush;

            // Is this a system table ?
            if (src_table.id < 2) {
                std::cout << "Skipped (SYSTEM TABLE)" << std::flush;
                continue;
            }

            // Is this table present in the list user has provided ?
            if (app_opts.tables.size()) {
                auto it = std::find(app_opts.tables.begin(), app_opts.tables.end(), src_table.name);
                if (it == app_opts.tables.end()) {
                    std::cout << "Skipped (no match --tables)" << std::flush;
                    continue;
                }
            }

            // Is this table present in the list user has excluded ?
            if (app_opts.xtables.size()) {
                auto it = std::find(app_opts.xtables.begin(), app_opts.xtables.end(), src_table.name);
                if (it != app_opts.xtables.end()) {
                    std::cout << "Skipped (match --xtables)" << std::flush;
                    continue;
                }
            }

            // Is table empty ?
            if (!src_table.stat.ms_entries && app_opts.noempty) {
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
                tgt_table_map =
                    tgt_txn.create_map(src_table.name, src_table_info.key_mode(), src_table_info.value_mode());
            } else {
                if (populated_on_target && !app_opts.upsert) {
                    std::cout << "Skipped (already populated on target and --upsert was not set)" << std::flush;
                    continue;
                }
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
            MDBX_put_flags_t put_flags{MDBX_put_flags_t::MDBX_UPSERT};
            if (!app_opts.upsert) {
                put_flags = (src_table_info.flags & MDBX_DUPSORT) ? MDBX_put_flags_t::MDBX_APPENDDUP
                                                                  : MDBX_put_flags_t::MDBX_APPEND;
            }

            auto data{src_table_crs.to_first(/*throw_notfound =*/false)};
            while (data) {
                tgt_table_crs.put(data.key, &data.value, put_flags);
                bytesWritten += (data.key.length() + data.value.length());
                if (bytesWritten > app_opts.commitsize) {
                    tgt_table_crs.close();
                    tgt_txn.commit();
                    tgt_txn = tgt_env.start_write();
                    tgt_table_map = tgt_txn.open_map(src_table.name);
                    tgt_table_crs = tgt_txn.open_cursor(tgt_table_map);
                    batch_committed = true;
                    bytesWritten = 0;
                }

                if (!--batch_size) {
                    progress.set_current(progress.get_current() + progress.get_increment_count());
                    std::cout << progress.print_interval(batch_committed ? 'W' : '.') << std::flush;
                    batch_committed = false;
                    batch_size = progress.get_increment_count();
                    if (shouldStop) break;
                }

                data = src_table_crs.to_next(/*throw_notfound =*/false);
            }

            progress.set_current(src_table.stat.ms_entries);
            std::cout << progress.print_interval(batch_committed ? 'W' : '.') << std::flush;

            // Close all
            if (!shouldStop && bytesWritten) {
                tgt_txn.commit();
            }
        }

        std::cout << "\n All done!" << std::endl;

    } catch (const std::exception& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    return retvar;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    DbOptions db_opts{};               // Common options for all actions
    FreeListOptions freelist_opts{};   // Options for freelist action
    ClearOptions clear_opts{};         // Options for clear action
    CompactOptions compact_opts{};     // Options for compact action
    CopyOptions copy_opts{};           // Options for copy action
    StageSetOptions stage_set_opts{};  // Options for stage set

    CLI::App app_main("Erigon db tool");

    CLI::Range range32(1u, UINT32_MAX);

    // Common CLI options
    app_main.add_option("--chaindata", db_opts.datadir, "Path to directory for mdbx.dat", false);
    app_main.add_flag("--shared", db_opts.shared, "Open database in shared mode");

    // List tables and gives info about storage
    auto& app_tables = *app_main.add_subcommand("tables", "List tables info and db info");

    auto& app_scan = *app_main.add_subcommand("scan", "Scans tables for real sizes");

    app_main.require_subcommand(1);  // One of the following subcommands is required

    // Provides detail of all free pages
    auto& app_freelist = *app_main.add_subcommand("freelist", "List free pages");
    app_freelist.add_flag("--detail", freelist_opts.details, "Gives detail for each FREE_DBI record");

    // Clear table tool
    auto& app_clear = *app_main.add_subcommand("clear", "Empties a named table");
    app_clear.add_option("--names", clear_opts.names, "Name of table to clear")->required();
    app_clear.add_flag("--drop", clear_opts.drop, "Drop table instead of emptying it");
    app_clear.add_flag("-Y,--yes", clear_opts.yes, "Assume yes to all requests of confirmation");

    // Compact
    auto& app_compact = *app_main.add_subcommand("compact", "Compacts an lmdb database");
    app_compact.add_option("--workdir", compact_opts.workdir, "Working directory (must exist)", false)
        ->required()
        ->check(CLI::ExistingDirectory);
    app_compact.add_flag("--replace", compact_opts.replace, "Replace original file with compacted");
    app_compact.add_flag("--nobak", compact_opts.nobak, "Don't create a bak copy of original when replacing");

    // Copy
    auto& app_copy = *app_main.add_subcommand("copy", "Copies an entire Erigon database or subset of tables");
    app_copy.add_option("--targetdir", copy_opts.targetdir, "Working directory (must exist)", false)
        ->required()
        ->check(CLI::ExistingDirectory);
    app_copy.add_flag("--create", copy_opts.create, "Create target database");
    app_copy.add_flag("--noempty", copy_opts.noempty, "Omit copying empty tables");
    app_copy.add_flag("--upsert", copy_opts.upsert, "Use upsert instead of append");
    app_copy.add_option("--tables", copy_opts.tables, "Copy only tables matching this list of names", true);
    app_copy.add_option("--xtables", copy_opts.xtables, "Don't copy tables matching this list of names", true);
    app_copy.add_option("--commit", copy_opts.commitsize_str, "Commit every this size bytes", true);

    // Schema
    auto& app_schema = *app_main.add_subcommand("schema", "Reports the schema version of Erigon DB");

    // Stages tool
    // List stages keys and their heights
    auto& app_stages = *app_main.add_subcommand("stages", "List stages and their actual heights");

    auto& app_stage_set = *app_main.add_subcommand("stageset", "Sets a stage to a new height");
    app_stage_set.add_option("--name", stage_set_opts.name, "Name of the stage to set", false)->required();
    app_stage_set.add_option("--height", stage_set_opts.height, "New height for stage", false)
        ->required()
        ->check(CLI::Range(0u, UINT32_MAX));

    CLI11_PARSE(app_main, argc, argv);

    // Cli args sanification for compact
    if (app_compact) {
        compact_opts.dir = fs::path(compact_opts.workdir);
        compact_opts.file = (compact_opts.dir / fs::path(db::kDbDataFileName));
        if (fs::exists(compact_opts.file)) {
            std::cout << " An " << db::kDbDataFileName << " file already present in workdir" << std::endl;
            return -1;
        }
    }

    // Cli args sanification for copy
    if (app_copy) {
        copy_opts.dir = fs::path(copy_opts.targetdir);
        copy_opts.file = (copy_opts.dir / fs::path(db::kDbDataFileName));
        if (fs::exists(copy_opts.file)) {
            copy_opts.filesize = fs::file_size(copy_opts.file);
            if (copy_opts.create) {
                std::cout << db::kDbDataFileName
                          << " file already present in target directory but you have set --create" << std::endl;
                return -1;
            }
        } else if (!copy_opts.create) {
            std::cout << db::kDbDataFileName << " not found in target directory. You may want to specify --create"
                      << std::endl;
            return -1;
        }

        auto tmpsize{parse_size(copy_opts.commitsize_str)};
        if (!tmpsize.has_value()) {
            std::cout << " Provided --commit size is invalid" << std::endl;
            return -1;
        }
        copy_opts.commitsize = std::max(*tmpsize, static_cast<uint64_t>(1ull << 20));
        tmpsize.reset();
    }

    if (app_tables) {
        return do_tables(db_opts);
    } else if (app_scan) {
        return do_scan(db_opts);
    } else if (app_stages) {
        return do_stages(db_opts);
    } else if (app_stage_set) {
        return do_stage_set(db_opts, stage_set_opts);
    } else if (app_freelist) {
        return do_freelist(db_opts, freelist_opts);
    } else if (app_clear) {
        return do_clear(db_opts, clear_opts);
    } else if (app_compact) {
        return do_compact(db_opts, compact_opts);
    } else if (app_copy) {
        return do_copy(db_opts, copy_opts);
    } else if (app_schema) {
        return do_schema(db_opts);
    } else {
        std::cerr << "No command specified" << std::endl;
    }

    return -1;
}
