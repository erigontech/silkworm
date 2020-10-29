/*
   Copyright 2020 The Silkworm Authors

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

#include <CLI/CLI.hpp>
#include <boost/bind.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <csignal>
#include <iostream>
#include <regex>
#include <silkworm/chain/config.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/types/block.hpp>
#include <string>

namespace bfs = boost::filesystem;
using namespace silkworm;

bool shouldStop{false};
int errorCode{0};

class Progress {
   public:
    Progress(uint32_t width) : bar_width_{width}, percent_step_{100u / width} {};
    ~Progress() = default;

    // Return current percentage
    uint32_t percent(void) {
        if (!max_counter_) return 100;
        if (!current_counter_) return 0;
        return (uint32_t)(current_counter_ * 100 / max_counter_);
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
        uint32_t percentage{(uint32_t)percent()};
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
    MDB_dbi id{0};
    std::string name{};
    MDB_stat stat{};
    size_t pages(void) { return stat.ms_branch_pages + stat.ms_leaf_pages + stat.ms_overflow_pages; }
    size_t size(void) { return pages() * stat.ms_psize; }
};

struct dbTablesInfo {
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
    size_t pages{ 0 };
    size_t size{0};
    std::vector<dbFreeEntry> entries{};
};

struct db_options_t {
    std::string datadir{silkworm::db::default_path()};  // Where data file is located
    std::string mapsize_str{};                          // Provided map_size literal
    uint64_t mapsize{0};                                // Computed map size
    bool exclusive{false};                              // Wheter or not try to gain exclusive access to db
    uint64_t filesize{0};                               // Size of data.mdb (not an option - only for convenience)
    bfs::path dir{};                                    // Path to data directory
    bfs::path file{};                                   // Path to data file
};

struct freelist_options_t {
    bool details{false};  // Wheter or not print detailed list
};

struct clear_options_t {
    std::vector<std::string> names{};  // Name of table(s) to clear
    bool drop{false};                  // Whether or not to drop table instead of clearing
};

struct compact_options_t {
    std::string workdir{};              // Where compacted file should be located
    bool replace{false};                // Wheter or not compacted file shoudl replace original one
    bool nobak{false};                  // Whether or not the original file should be renamed to bak
    bfs::path dir{};                    // Path to target data directory (i.e. workdir)
    bfs::path file{};                   // Path to target data file
};

struct copy_options_t
{
    std::string targetdir{};            // Target directory of database
    bool create{false};                 // Whether or not new data.mdb have to be created
    bool noempty{false};                // Omit copying a table when empty
    bool upsert{false};                 // Copy using upsert instead of append (reuses free pages if any)
    std::string newmapsize_str{};       // Size of target file (as input literal)
    uint64_t newmapsize{0};             // Computed map size
    std::vector<std::string> tables{};  // A limited set of table names
    std::string commitsize_str{"5GB"};  // Provided commit size literal default 5GB
    uint64_t commitsize{0};             // Computed commit size
    bfs::path dir{};                    // Path to target data directory (i.e. workdir)
    bfs::path file{};                   // Path to target data file
    size_t filesize{0};                 // Size of target file if exists
};

void sig_handler(int signum) {
    (void)signum;
    std::cout << std::endl << "Request for termination intercepted. Stopping ..." << std::endl << std::endl;
    shouldStop = true;
}

std::optional<uint64_t> parse_size(const std::string& strsize) {
    if (strsize.empty()) return {0};

    std::regex pattern{"^([0-9]{1,})([\\ ]{0,})?(B|KB|MB|GB|TB|EB)?$"};
    std::smatch matches;
    if (!std::regex_search(strsize, matches, pattern, std::regex_constants::match_default)) {
        return std::nullopt;
    };

    uint64_t number{std::strtoull(matches[1].str().c_str(), nullptr, 10)};

    if (matches[3].length() == 0) {
        return {number};
    }
    std::string suffix = matches[3].str();
    if (suffix == "B") {
        return {number};
    } else if (suffix == "KB") {
        return {number * (1ull << 10)};
    } else if (suffix == "MB") {
        return {number * (1ull << 20)};
    } else if (suffix == "GB") {
        return {number * (1ull << 30)};
    } else if (suffix == "TB") {
        return {number * (1ull << 40)};
    } else if (suffix == "EB") {
        return {number * (1ull << 50)};
    } else {
        return std::nullopt;
    }
}

std::shared_ptr<lmdb::Environment> open_db(db_options_t& db_opts, bool readonly) {
    try {
        lmdb::options opts{};
        if (db_opts.mapsize) opts.map_size = db_opts.mapsize;
        opts.read_only = readonly;
        return lmdb::get_env(db_opts.datadir.c_str(), opts);

    } catch (const std::exception& ex) {
        std::cout << ex.what() << std::endl;
        return nullptr;
    }
}

int do_clear(db_options_t& db_opts, clear_options_t& app_opts) {
    int retvar{0};
    std::shared_ptr<lmdb::Environment> lmdb_env{open_db(db_opts, false)};  // Main lmdb environment
    std::unique_ptr<lmdb::Transaction> lmdb_txn{nullptr};                             // Main lmdb transaction
    std::unique_ptr<lmdb::Table> lmdb_tbl{nullptr};                                   // Table name to be cleared

    try {
        if (!lmdb_env) {
            throw std::runtime_error("Could not open LMDB environment");
        }
        lmdb_txn = lmdb_env->begin_rw_transaction();

        for (const auto& tablename : app_opts.names) {
            lmdb_tbl = lmdb_txn->open({tablename.c_str()});
            size_t rcount{0};
            lmdb::err_handler(lmdb_tbl->get_rcount(&rcount));
            if (!app_opts.drop && !rcount) {
                std::cout << " Table " << tablename << " is already empty. Skipping" << std::endl;
            } else {
                std::cout << "\n"
                          << (app_opts.drop ? "Dropping" : "Emptying") << " table " << tablename << " (" << rcount
                          << " records)" << std::endl;
                lmdb::err_handler(app_opts.drop ? lmdb_tbl->drop() : lmdb_tbl->clear());
                lmdb_tbl->close();
            }
            lmdb_tbl.reset();
        }

        std::cout << "Committing ... " << std::endl;
        lmdb::err_handler(lmdb_txn->commit());
        std::cout << "Success !" << std::endl;

    } catch (std::logic_error& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    } catch (lmdb::exception& ex) {
        // This handles specific lmdb errors
        std::cout << ex.err() << " " << ex.what() << std::endl;
        retvar = -1;
    } catch (std::runtime_error& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    lmdb_tbl.reset();
    lmdb_txn.reset();
    lmdb_env.reset();

    return retvar;
}

dbFreeInfo get_freeInfo(std::shared_ptr<lmdb::Environment>& env) {

    std::unique_ptr<lmdb::Transaction> tx{env->begin_ro_transaction()};
    std::unique_ptr<lmdb::Table> free_db{tx->open(lmdb::FREE_DBI)};

    dbFreeInfo ret{};
    MDB_stat stat{};
    MDB_val key, data;
    lmdb::err_handler(free_db->get_stat(&stat));
    int rc{free_db->get_first(&key, &data)};
    while (rc == MDB_SUCCESS) {
        size_t txid = *(static_cast<size_t*>(key.mv_data));
        size_t pagesCount = *(static_cast<size_t*>(data.mv_data));
        size_t pagesSize = pagesCount * stat.ms_psize;
        ret.pages += pagesCount;
        ret.size += pagesSize;
        ret.entries.push_back({txid, pagesCount, pagesSize});
        rc = free_db->get_next(&key, &data);
    }
    if (rc != MDB_NOTFOUND) {
        lmdb::err_handler(rc);
    }

    return ret;
}

dbTablesInfo get_tablesInfo(std::shared_ptr<lmdb::Environment>& env) {

    std::unique_ptr<lmdb::Transaction> tx{env->begin_ro_transaction()};

    dbTablesInfo ret{};
    MDB_val key, data;

    std::unique_ptr<lmdb::Table> unnamed{tx->open(lmdb::FREE_DBI)};
    dbTableEntry* table;

    unnamed = tx->open(lmdb::FREE_DBI);
    table = new dbTableEntry{unnamed->get_dbi(), unnamed->get_name()};
    lmdb::err_handler(unnamed->get_stat(&table->stat));
    ret.pageSize = table->stat.ms_psize;
    ret.pages += table->pages();
    ret.size += table->size();
    ret.tables.push_back(*table);

    unnamed.reset();
    unnamed = tx->open(lmdb::MAIN_DBI);
    table = new dbTableEntry{unnamed->get_dbi(), unnamed->get_name()};
    lmdb::err_handler(unnamed->get_stat(&table->stat));
    ret.pages += table->pages();
    ret.size += table->size();
    ret.tables.push_back(*table);

    int rc{unnamed->get_first(&key, &data)};
    while (rc == MDB_SUCCESS) {
        // if (data.mv_size < sizeof(size_t)) {
        //    lmdb::err_handler(MDB_INVALID);
        //}

        auto named = tx->open({(const char*)key.mv_data});
        table = new dbTableEntry{named->get_dbi(), named->get_name()};
        lmdb::err_handler(named->get_stat(&table->stat));
        ret.pages += table->pages();
        ret.size += table->size();
        ret.tables.push_back(*table);
        rc = unnamed->get_next(&key, &data);
    }
    if (rc != MDB_NOTFOUND) {
        lmdb::err_handler(rc);
    }

    return ret;
}

int do_tables(db_options_t& db_opts) {
    static std::string fmt_hdr{" %3s %-24s %10s %2s %10s %10s %10s %12s"};
    static std::string fmt_row{" %3i %-24s %10u %2u %10u %10u %10u %12u"};

    int retvar{0};
    std::shared_ptr<lmdb::Environment> lmdb_env{open_db(db_opts, true)};  // Main lmdb environment

    try {

        if (!lmdb_env) throw std::runtime_error("Could not open LMDB environment");

        //lmdb_txn = lmdb_env->begin_ro_transaction();

        auto freeInfo{get_freeInfo(lmdb_env)};
        auto tablesInfo{get_tablesInfo(lmdb_env)};
        std::cout << "\n Database tables    : " << tablesInfo.tables.size() << std::endl;
        std::cout << " Database page size : " << tablesInfo.pageSize << " \n" << std::endl;

        if (tablesInfo.tables.size()) {
            std::cout << (boost::format(fmt_hdr) % "Dbi" % "Table name" % "Records" % "D" % "Branch" % "Leaf" %
                          "Overflow" % "Size")
                      << std::endl;
            std::cout << (boost::format(fmt_hdr) % std::string(3, '-') % std::string(24, '-') % std::string(10, '-') %
                          std::string(2, '-') % std::string(10, '-') % std::string(10, '-') % std::string(10, '-') %
                          std::string(12, '-'))
                      << std::endl;

            for (dbTableEntry item : tablesInfo.tables) {
                std::cout << (boost::format(fmt_row) % item.id % item.name % item.stat.ms_entries % item.stat.ms_depth %
                              item.stat.ms_branch_pages % item.stat.ms_leaf_pages % item.stat.ms_overflow_pages %
                              item.size())
                          << std::endl;
            }
        }

        std::cout << "\n Database map size    : " << (boost::format("%13u") % db_opts.mapsize) << std::endl;
        std::cout << " Size of file on disk : " << (boost::format("%13u") % db_opts.filesize) << std::endl;
        std::cout << " Data pages count     : " << (boost::format("%13u") % tablesInfo.pages) << std::endl;
        std::cout << " Data pages size      : " << (boost::format("%13u") % tablesInfo.size) << std::endl;
        std::cout << " Reclaimable pages    : " << (boost::format("%13u") % freeInfo.pages) << std::endl;
        std::cout << " Reclaimable size     : " << (boost::format("%13u") % freeInfo.size) << std::endl;
        std::cout << " Free space available : "
                  << (boost::format("%13u") % (db_opts.mapsize - tablesInfo.size + freeInfo.size)) << std::endl;

    } catch (lmdb::exception& ex) {
        std::cout << ex.err() << " " << ex.what() << std::endl;
        retvar = -1;
    } catch (std::runtime_error& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    lmdb_env.reset();
    return retvar;
}

int do_freelist(db_options_t& db_opts, freelist_options_t& app_opts) {
    static std::string fmt_hdr{"%9s %9s %12s"};
    static std::string fmt_row{"%9u %9u %12u"};

    int retvar{0};
    std::shared_ptr<lmdb::Environment> lmdb_env{open_db(db_opts, true)};  // Main lmdb environment

    try {

        if (!lmdb_env) throw std::runtime_error("Could not open LMDB environment");
        auto freeInfo{get_freeInfo(lmdb_env)};
        if (freeInfo.entries.size() && app_opts.details) {

            std::cout << std::endl;
            std::cout << (boost::format(fmt_hdr) % "TxId" % "Pages" % "Size") << std::endl;
            std::cout << (boost::format(fmt_hdr) % std::string(9, '-') % std::string(9, '-') % std::string(12, '-'))
                      << std::endl;
            for (auto& item : freeInfo.entries) {
                std::cout << (boost::format(fmt_row) % item.id % item.pages % item.size)
                          << std::endl;
            }
        }
        std::cout << "\n Total free pages     : " << boost::format("%13u") % freeInfo.pages << "\n"
                  << " Total free size      : " << boost::format("%13u") % freeInfo.size << std::endl;

    } catch (lmdb::exception& ex) {
        std::cout << ex.err() << " " << ex.what() << std::endl;
        retvar = -1;
    } catch (std::runtime_error& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    lmdb_env.reset();
    return retvar;
}

int do_compact(db_options_t& db_opts, compact_options_t& app_opts) {
    int retvar{0};
    std::shared_ptr<lmdb::Environment> lmdb_src_env{open_db(db_opts, false)};  // Main lmdb environment
    std::shared_ptr<lmdb::Environment> lmdb_tgt_env{nullptr};                  // Target lmdb environment

    try {

        if (!lmdb_src_env) throw std::runtime_error("Could not open LMDB environment");

        // Ensure target working directory has enough free space
        // at least the size of origin db
        auto target_path = bfs::path{app_opts.workdir};
        auto target_file = bfs::path{target_path / bfs::path{"data.mdb"}};
        auto target_space = bfs::space(target_path);
        if (target_space.free <= db_opts.filesize) {
            throw std::runtime_error("Insufficient disk space on working directory");
        }

        std::cout << " Compacting " << db_opts.file << "\n into " << target_path << "\n Please be patient as there is no progress report ..."
                  << std::endl;
        lmdb::err_handler(mdb_env_copy2(*(lmdb_src_env->handle()), target_path.string().c_str(), MDB_CP_COMPACT));
        std::cout << "\n Database compaction " << (shouldStop ? "aborted !" : "completed ...") << std::endl;

        if (!shouldStop) {
            // Do we have a valid compacted file on disk ?
            // replace source with target
            if (!bfs::exists(target_file)) {
                throw std::runtime_error("Can't locate compacted data.mdb");
            }

            // Do we have to replace original file ?
            if (app_opts.replace) {
                // Create a backup copy before replacing ?
                if (!app_opts.nobak) {
                    std::cout << " Creating backup copy of origin db ..." << std::endl;
                    bfs::path source_bak{db_opts.file.parent_path() / bfs::path{"data.mdb.bak"}};
                    if (bfs::exists(source_bak)) bfs::remove(source_bak);
                    bfs::rename(db_opts.file, source_bak);
                }

                std::cout << " Replacing origin db with compacted ..." << std::endl;
                if (bfs::exists(db_opts.file)) bfs::remove(db_opts.file);
                bfs::rename(target_file, db_opts.file);
            }
        }

        std::cout << " All done !" << std::endl;

    } catch (const std::exception& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    lmdb_src_env.reset();
    lmdb_tgt_env.reset();
    return retvar;
}

int do_copy(db_options_t& db_opts, copy_options_t& app_opts) {

    int retvar{ 0 };
    std::shared_ptr<lmdb::Environment> lmdb_src_env{ open_db(db_opts, true) };  // Main lmdb environment

    try
    {
        if (!lmdb_src_env) throw std::runtime_error("Could not open source LMDB environment");
        db_options_t tgt_opts{};
        tgt_opts.mapsize = app_opts.newmapsize;
        tgt_opts.datadir = app_opts.targetdir;
        tgt_opts.file = app_opts.file;
        tgt_opts.dir = app_opts.dir;
        std::shared_ptr<lmdb::Environment> lmdb_tgt_env{open_db(tgt_opts, false)};
        if (!lmdb_tgt_env) throw std::runtime_error("Could not open target LMDB environment");

        // Get free info and tables from both source and target environment
        auto src_freeInfo = get_freeInfo(lmdb_src_env);
        auto src_tableInfo = get_tablesInfo(lmdb_src_env);
        auto tgt_freeInfo = get_freeInfo(lmdb_tgt_env);
        auto tgt_tableInfo = get_tablesInfo(lmdb_tgt_env);

        // Check source db has tables to copy besides the two system tables
        if (src_tableInfo.tables.size() < 3) {
            throw std::runtime_error("Source db has no tables to copy.");
        }

        size_t bytesWritten{ 0 };
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

            // Is this a known table ?
            std::optional<lmdb::TableConfig> src_config{db::table::get_config(src_table.name)};
            if (!src_config.has_value()) {
                std::cout << "Skipped (unknown table)" << std::flush;
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

            // Is table empty ?
            if (!src_table.stat.ms_entries && app_opts.noempty) {
                std::cout << "Skipped (--noempty)" << std::flush;
                continue;
            }

            // Is source table already present in target db ?
            bool exists_on_target{false};
            if(tgt_tableInfo.tables.size())
            {
                auto it = std::find_if(tgt_tableInfo.tables.begin(), tgt_tableInfo.tables.end(), boost::bind(&dbTableEntry::name, _1) == src_table.name);
                if (it != tgt_tableInfo.tables.end()) exists_on_target = true;
            }


            // Ensure there is enough free space on target
            // In case the user have opted for Upsert mode we need to
            // compute all reclaimable space + the difference amongst data size and map_size
            // In case we go for append then data is appended to the end of file
            size_t available_space =
                (app_opts.upsert ? tgt_freeInfo.size : 0) + (tgt_opts.mapsize - tgt_tableInfo.size);
            if (available_space < src_table.size()) {
                tgt_opts.mapsize += (src_table.size() - available_space);
                // Round map size to nearest multiple of commit size
                tgt_opts.mapsize =
                    ((tgt_opts.mapsize + app_opts.commitsize - 1) / app_opts.commitsize) * app_opts.commitsize;
                lmdb_tgt_env->set_mapsize(tgt_opts.mapsize);
            }

            // Ready to copy
            std::unique_ptr<lmdb::Transaction> lmdb_src_txn{ lmdb_src_env->begin_ro_transaction() };
            std::unique_ptr<lmdb::Table> lmdb_src_tbl{lmdb_src_txn->open(*src_config)};
            std::unique_ptr<lmdb::Transaction> lmdb_tgt_txn{ lmdb_tgt_env->begin_rw_transaction() };
            std::unique_ptr<lmdb::Table> lmdb_tgt_tbl{lmdb_tgt_txn->open(*src_config, (exists_on_target ? 0u : (unsigned int)MDB_CREATE))};

            // If table exists on target and is populated and NOT --upsert then
            // skip with error
            if (exists_on_target) {
                MDB_stat stat{};
                lmdb::err_handler(lmdb_tgt_tbl->get_stat(&stat));
                if (stat.ms_entries && !app_opts.upsert) {
                    std::cout << "Skipped (already populated on target and --upsert was not set)" << std::flush;
                    continue;
                }
            }

            // Copy Stuff
            unsigned int flags{0};
            if (!app_opts.upsert) {
                flags |= (((src_config->flags & MDB_DUPSORT) == MDB_DUPSORT) ? MDB_APPENDDUP : MDB_APPEND);
            }

            // Loop source and write into target
            Progress progress{50};
            progress.set_task_count(src_table.stat.ms_entries);
            size_t batch_size{progress.get_increment_count()};
            bool batch_committed{false};
            MDB_val key, data;
            int rc{lmdb_src_tbl->get_first(&key, &data)};
            while (rc == MDB_SUCCESS) {
                lmdb::err_handler(lmdb_tgt_tbl->put(&key, &data, flags));
                bytesWritten += key.mv_size + data.mv_size;
                if (bytesWritten > app_opts.commitsize) {
                    lmdb_tgt_tbl.reset();
                    lmdb::err_handler(lmdb_tgt_txn->commit());
                    lmdb_tgt_txn.reset();
                    lmdb_tgt_txn = lmdb_tgt_env->begin_rw_transaction();
                    lmdb_tgt_tbl = lmdb_tgt_txn->open(*src_config);
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

                rc = lmdb_src_tbl->get_next(&key, &data);
            }
            if (rc != MDB_NOTFOUND) lmdb::err_handler(rc);
            progress.set_current(src_table.stat.ms_entries);
            std::cout << progress.print_interval(batch_committed ? 'W' : '.') << std::flush;

            // Close all
            lmdb_src_tbl.reset();
            lmdb_tgt_tbl.reset();
            lmdb_src_txn.reset();
            if (!shouldStop && bytesWritten) {
                lmdb::err_handler(lmdb_tgt_txn->commit());
            }
            lmdb_tgt_txn.reset();

            // Recompute target data
            if (!shouldStop) {
                tgt_freeInfo = get_freeInfo(lmdb_tgt_env);
                tgt_tableInfo = get_tablesInfo(lmdb_tgt_env);
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

    db_options_t db_opts{};              // Common options for all actions
    freelist_options_t freelist_opts{};  // Options for freelist action
    clear_options_t clear_opts{};        // Options for clear action
    compact_options_t compact_opts{};    // Options for compact action
    copy_options_t copy_opts{};          // Options for copy action

    CLI::App app_main("Turbo-Geth db tool");

    CLI::Range range32(1u, UINT32_MAX);

    // Common CLI options
    app_main.add_option("--datadir", db_opts.datadir, "Path to directory for data.mdb", false);
    app_main.add_option("--lmdb.mapSize", db_opts.mapsize_str, "Lmdb map size", true);
    //app_main.add_flag("--exclusive", db_opts.exclusive, "Exclusive access to db");

    // List tables and gives info about storage
    auto& app_tables = *app_main.add_subcommand("tables", "List tables info and db info");

    // Provides detail of all free pages
    auto& app_freelist = *app_main.add_subcommand("freelist", "List free pages");
    app_freelist.add_flag("--detail", freelist_opts.details, "Gives detail for each FREE_DBI record");

    // Clear table tool
    auto& app_clear = *app_main.add_subcommand("clear", "Empties a named table");
    app_clear.add_option("--names", clear_opts.names, "Name of table to clear")->required();
    app_clear.add_flag("--drop", clear_opts.drop, "Drop table instead of emptying it");

    // Compact
    auto& app_compact = *app_main.add_subcommand("compact", "Compacts an lmdb database");
    app_compact.add_option("--workdir", compact_opts.workdir, "Working directory (must exist)", false)
        ->required()
        ->check(CLI::ExistingDirectory);
    app_compact.add_flag("--replace", compact_opts.replace, "Replace original file with compacted");
    app_compact.add_flag("--nobak", compact_opts.nobak, "Don't create a bak copy of original when replacing");

    // Copy
    auto& app_copy = *app_main.add_subcommand("copy", "Copies an entire TG database or subset of tables");
    app_copy.add_option("--targetdir", copy_opts.targetdir, "Working directory (must exist)", false)
        ->required()
        ->check(CLI::ExistingDirectory);
    app_copy.add_flag("--create", copy_opts.create, "Create target database");
    app_copy.add_flag("--noempty", copy_opts.noempty, "Omit copying empty tables");
    app_copy.add_flag("--upsert", copy_opts.upsert, "Use upsert instead of append");
    app_copy.add_option("--new.mapSize", copy_opts.newmapsize_str, "Created db file should have this map size", true);
    app_copy.add_option("--tables", copy_opts.tables, "Copy only tables matching this list of names", true);
    app_copy.add_option("--commit", copy_opts.commitsize_str, "Commit every this size bytes", true);


    CLI11_PARSE(app_main, argc, argv);

    // Check provided data file exists
    db_opts.dir = bfs::path(db_opts.datadir);
    db_opts.file = (db_opts.dir / bfs::path("data.mdb"));
    if (!bfs::exists(db_opts.file) || !bfs::is_regular_file(db_opts.file)) {
        std::cout << " " << db_opts.file.string() << " not found" << std::endl;
        return -1;
    }
    db_opts.filesize = bfs::file_size(db_opts.file);

    std::optional<uint64_t> tmpsize{parse_size(db_opts.mapsize_str)};
    if (!tmpsize.has_value()) {
        std::cout << " Provided --lmdb.mapSize is invalid" << std::endl;
        return -1;
    }
    db_opts.mapsize = std::max(*tmpsize, db_opts.filesize);  // Do not accept mapSize below filesize
    tmpsize.reset();

    // Adjust mapSize to a multiple of page_size
    size_t host_page_size{boost::interprocess::mapped_region::get_page_size()};
    db_opts.mapsize = ((db_opts.mapsize + host_page_size - 1) / host_page_size) * host_page_size;

    // Cli args sanification for compact
    if (app_compact) {
        compact_opts.dir = bfs::path(compact_opts.workdir);
        compact_opts.file = (compact_opts.dir / bfs::path("data.mdb"));
        if (bfs::exists(compact_opts.file)) {
            std::cout << " An data.mdb file already present in workdir" << std::endl;
            return -1;
        }
    }

    // Cli args sanification for copy
    if (app_copy) {

        copy_opts.dir = bfs::path(copy_opts.targetdir);
        copy_opts.file = (copy_opts.dir / bfs::path("data.mdb"));
        if (bfs::exists(copy_opts.file)) {
            copy_opts.filesize = bfs::file_size(copy_opts.file);
            if (copy_opts.create) {
                std::cout << " Data.mdb file already present in target directory but you have set --create"
                          << std::endl;
                return -1;
            }
        } else if (!copy_opts.create) {
            std::cout << " Data.mdb not found target directory. You may want to specify --create" << std::endl;
            return -1;
        }

        tmpsize = parse_size(copy_opts.newmapsize_str);
        if (!tmpsize.has_value()) {
            std::cout << " Provided --new.mapSize is invalid" << std::endl;
            return -1;
        }
        copy_opts.newmapsize = *tmpsize;
        if (copy_opts.filesize) {
            copy_opts.newmapsize = std::max((size_t)*tmpsize, copy_opts.filesize);  // Do not accept mapSize below filesize
        }
        tmpsize.reset();

        if (copy_opts.create && !copy_opts.newmapsize) {
            std::cout << " --create has been set. Need to provide --new.mapSize too" << std::endl;
            return -1;
        }

        tmpsize = parse_size(copy_opts.commitsize_str);
        if (!tmpsize.has_value()) {
            std::cout << " Provided --commit size is invalid" << std::endl;
            return -1;
        }
        copy_opts.commitsize = std::max((uint64_t)*tmpsize, (uint64_t)(1ull << 20));
        tmpsize.reset();
    }

    if (app_tables) {
        return do_tables(db_opts);
    } else if (app_freelist) {
        return do_freelist(db_opts, freelist_opts);
    } else if (app_clear) {
        return do_clear(db_opts, clear_opts);
    } else if (app_compact) {
        return do_compact(db_opts, compact_opts);
    } else if (app_copy) {
        return do_copy(db_opts, copy_opts);
    } else {
        std::cerr << "No command specified" << std::endl;
    }

    return -1;
}
