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

struct dbTableEntry {
    MDB_dbi id{0};
    std::string name{};
    MDB_stat stat{};
};

struct dbFreeEntry {
    size_t transactionId{0};
    size_t freePagesCount{0};
    size_t freePagesSize{0};
};

struct dbFreeInfo {
    size_t totalFreePagesCount{ 0 };
    size_t totalFreePagesSize{ 0 };
    std::vector<dbFreeEntry> freePagesDetail{};
};

void sig_handler(int signum) {
    (void)signum;
    std::cout << std::endl << "Request for termination intercepted. Stopping ..." << std::endl << std::endl;
    shouldStop = true;
}

std::optional<uint64_t> parse_size(const std::string& strsize) {
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

int do_drop(std::string datadir, std::optional<uint64_t> mapsize, std::string tablename, bool del) {
    int retvar{0};
    std::shared_ptr<lmdb::Environment> lmdb_env{nullptr};  // Main lmdb environment
    std::unique_ptr<lmdb::Transaction> lmdb_txn{nullptr};  // Main lmdb transaction
    std::unique_ptr<lmdb::Table> lmdb_tbl{nullptr};        // Table name to be cleared

    try {
        // Open db and start a rw transaction
        lmdb::options opts{};
        if (mapsize.has_value()) {
            opts.map_size = *mapsize;
        }
        opts.read_only = false;
        lmdb_env = lmdb::get_env(datadir.c_str(), opts);
        lmdb_txn = lmdb_env->begin_rw_transaction();
        lmdb_tbl = lmdb_txn->open({tablename.c_str()});

        size_t rcount{0};
        lmdb::err_handler(lmdb_tbl->get_rcount(&rcount));
        if (!del && !rcount) {
            throw std::logic_error("Table " + tablename + " is already empty.");
        }

        std::cout << "\n"
                  << (del ? "Deleting" : "Emptying") << " table " << tablename << " (" << rcount << " records)"
                  << std::endl;
        lmdb::err_handler(del ? lmdb_tbl->drop() : lmdb_tbl->clear());
        lmdb_tbl->close();

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

std::optional<dbFreeInfo> get_freeInfo(std::unique_ptr<lmdb::Transaction>& tx) {

    dbFreeInfo ret{};
    try
    {
        MDB_stat stat;
        auto lmdb_free = tx->open(0);
        lmdb::err_handler(lmdb_free->get_stat(&stat));

        MDB_val key, data;
        int rc{ MDB_SUCCESS };
        lmdb::err_handler(lmdb_free->get_first(&key, &data));
        while (rc == MDB_SUCCESS)
        {
            size_t txid = *(static_cast<size_t*>(key.mv_data));
            size_t pagesCount = *(static_cast<size_t*>(data.mv_data));
            size_t pagesSize = pagesCount * stat.ms_psize;
            ret.totalFreePagesCount += pagesCount;
            ret.totalFreePagesSize += pagesSize;
            ret.freePagesDetail.push_back({ txid, pagesCount, pagesSize });
            rc = lmdb_free->get_next(&key, &data);
        }
        if (rc != MDB_NOTFOUND) {
            lmdb::err_handler(rc);
        }
    } catch (const std::exception&)
    {
        return std::nullopt;
    }

    return {ret};
}

std::vector<dbTableEntry> get_tables(std::unique_ptr<lmdb::Transaction>& tx) {
    std::vector<dbTableEntry> ret{};
    MDB_val key, data;

    auto unnamed = tx->open(lmdb::FREE_DBI);
    ret.push_back({unnamed->get_dbi(), unnamed->get_name()});
    lmdb::err_handler(unnamed->get_stat(&ret.back().stat));

    unnamed.reset();
    unnamed = tx->open(lmdb::MAIN_DBI);  // Opens unnamed table (every lmdb has one)
    ret.push_back({unnamed->get_dbi(), unnamed->get_name()});
    lmdb::err_handler(unnamed->get_stat(&ret.back().stat));
    if (ret.back().stat.ms_entries) {
        lmdb::err_handler(unnamed->get_first(&key, &data));
        while (!shouldStop) {
            if (data.mv_size < sizeof(size_t)) {
                lmdb::err_handler(MDB_INVALID);
            }
            auto named = tx->open({(const char*)key.mv_data});
            ret.push_back(
                {named->get_dbi(), named->get_name()});
            lmdb::err_handler(named->get_stat(&ret.back().stat));
            int rc{unnamed->get_next(&key, &data)};
            if (rc == MDB_NOTFOUND) break;
            lmdb::err_handler(rc);
        }
    }
    return ret;
}

int do_tables(std::string datadir, size_t file_size, std::optional<uint64_t> mapsize) {


    static std::string fmt_hdr{ " %3s %-24s %10s %2s %10s %10s %10s %12s" };
    static std::string fmt_row{ " %3i %-24s %10u %2u %10u %10u %10u %12u" };

    int retvar{0};
    std::shared_ptr<lmdb::Environment> lmdb_env{nullptr};  // Main lmdb environment
    std::unique_ptr<lmdb::Transaction> lmdb_txn{nullptr};  // Main lmdb transaction

    try {
        // Open db and start transaction
        lmdb::options opts{};
        if (mapsize.has_value()) {
            opts.map_size = *mapsize;
        }
        opts.read_only = true;
        lmdb_env = lmdb::get_env(datadir.c_str(), opts);
        lmdb_txn = lmdb_env->begin_ro_transaction();

        auto freeInfo = get_freeInfo(lmdb_txn);
        if (!freeInfo.has_value()) {
            throw std::runtime_error("Could not retrieve freeinfo");
        }

        std::vector<dbTableEntry> entries{get_tables(lmdb_txn)};
        size_t items_size{0};
        std::cout << "\n Database tables    : " << entries.size() << std::endl;

        if (entries.size()) {

            std::cout << " Database page size : " << entries.begin()->stat.ms_psize << " \n" << std::endl;

            std::cout << (boost::format(fmt_hdr) % "Dbi" % "Table name" % "Records" % "D" % "Branch" % "Leaf" %
                          "Overflow" % "Size")
                      << std::endl;
            std::cout << (boost::format(fmt_hdr) % std::string(3, '-') % std::string(24, '-') % std::string(10, '-') %
                          std::string(2, '-') % std::string(10, '-') % std::string(10, '-') % std::string(10, '-') %
                          std::string(12, '-'))
                      << std::endl;

            for (dbTableEntry item : entries) {
                size_t item_size{item.stat.ms_psize *
                                 (item.stat.ms_leaf_pages + item.stat.ms_branch_pages + item.stat.ms_overflow_pages)};
                items_size += item_size;
                std::cout << (boost::format(fmt_row) % item.id % item.name % item.stat.ms_entries % item.stat.ms_depth %
                              item.stat.ms_branch_pages % item.stat.ms_leaf_pages % item.stat.ms_overflow_pages % item_size)
                          << std::endl;
            }
        }

        std::cout << "\n Database map size    : " << (boost::format("%13u") % opts.map_size) << std::endl;
        std::cout << " Size of file on disk : " << (boost::format("%13u") % file_size) << std::endl;
        std::cout << " Size of data in file : " << (boost::format("%13u") % items_size) << std::endl;
        std::cout << " Reclaimable pages    : " << (boost::format("%13u") % freeInfo->totalFreePagesCount) << std::endl;
        std::cout << " Reclaimable size     : " << (boost::format("%13u") % freeInfo->totalFreePagesSize) << std::endl;
        std::cout << " Free space available : " << (boost::format("%13u") % (opts.map_size - items_size + freeInfo->totalFreePagesSize)) << std::endl;

    } catch (lmdb::exception& ex) {
        std::cout << ex.err() << " " << ex.what() << std::endl;
        retvar = -1;
    } catch (std::runtime_error& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    lmdb_txn.reset();
    lmdb_env.reset();
    return retvar;
}

int do_freelist(std::string datadir, std::optional<uint64_t> mapsize, bool txids) {

    static std::string fmt_hdr{ "%9s %9s %12s" };
    static std::string fmt_row{ "%9u %9u %12u" };

    int retvar{0};
    std::shared_ptr<lmdb::Environment> lmdb_env{nullptr};  // Main lmdb environment
    std::unique_ptr<lmdb::Transaction> lmdb_txn{nullptr};  // Main lmdb transaction
    std::unique_ptr<lmdb::Table> lmdb_free{nullptr};       // Free dbi

    try
    {
        // Open db and start transaction
        lmdb::options opts{};
        if (mapsize.has_value()) {
            opts.map_size = *mapsize;
        }
        opts.read_only = true;
        lmdb_env = lmdb::get_env(datadir.c_str(), opts);
        lmdb_txn = lmdb_env->begin_ro_transaction();

        auto freeInfo = get_freeInfo(lmdb_txn);
        if (!freeInfo.has_value()) {
            throw std::runtime_error("Could not get Free info");
        }
        if (freeInfo->freePagesDetail.size() && txids) {
            std::cout << (boost::format(fmt_hdr) % "TxId" % "Free pages" % "Free Size") << std::endl;
            std::cout << (boost::format(fmt_hdr) % std::string(9, '-') % std::string(9, '-') % std::string(12, '-')) << std::endl;
            for (auto item : freeInfo->freePagesDetail) {
                std::cout << (boost::format(fmt_row) % item.transactionId % item.freePagesCount % item.freePagesSize) << std::endl;
            }
        }

        std::cout << "\n Total free pages : " << freeInfo->totalFreePagesCount << std::endl;
        std::cout << " Total free size  : " << freeInfo->totalFreePagesSize << std::endl;

    } catch (lmdb::exception& ex) {
        std::cout << ex.err() << " " << ex.what() << std::endl;
        retvar = -1;
    } catch (std::runtime_error& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    lmdb_free.reset();
    lmdb_txn.reset();
    lmdb_env.reset();
    return retvar;

}

int do_compact(std::string datadir, std::optional<uint64_t> mapsize, std::string workdir, bool keep, bool copy) {
    int retvar{0};
    std::shared_ptr<lmdb::Environment> lmdb_src_env{nullptr};  // Source lmdb environment
    std::shared_ptr<lmdb::Environment> lmdb_tgt_env{nullptr};  // Target lmdb environment

    try {
        bfs::path source{bfs::path{datadir} / bfs::path{"data.mdb"}};
        size_t source_size{bfs::file_size(source)};
        bfs::path target{bfs::path{workdir} / bfs::path{"data.mdb"}};

        // Do not overwrite target
        if (bfs::exists(target)) {
            throw std::runtime_error("File data.mdb already existing in working directory");
        }

        // Ensure target working directory has enough free space
        // at least the size of source
        auto target_space = bfs::space(target.parent_path());
        if (target_space.free <= source_size) {
            throw std::runtime_error("Insufficient disk space on working directory");
        }

        // Open db and start transaction
        lmdb::options src_opts{};
        src_opts.read_only = true;
        if (mapsize.has_value()) {
            src_opts.map_size = *mapsize;
        }
        lmdb_src_env = lmdb::get_env(datadir.c_str(), src_opts);
        std::cout << " Compacting " << source.string() << "\n into " << target.string() << "\n Please be patient ..."
                  << std::endl;
        if (!copy) {
            lmdb::err_handler(mdb_env_copy2(*(lmdb_src_env->handle()), workdir.c_str(), MDB_CP_COMPACT));
        } else {
            // We traverse all populated tables and copy only their data
            std::unique_ptr<lmdb::Transaction> src_txn{lmdb_src_env->begin_ro_transaction()};
            auto tables = get_tables(src_txn);
            size_t data_size{0};

            // Compute size of data we need to copy
            for (dbTableEntry table : tables) {
                if (table.id < 2) continue;  // Dont account data from reserved databases
                data_size += table.stat.ms_psize *
                             (table.stat.ms_leaf_pages + table.stat.ms_branch_pages + table.stat.ms_overflow_pages);
            }

            // Add extra 50 Mb to fit
            // Should actually compute the real reclaimable space traversing free_dbi
            // But this is an experiment
            data_size += (500ull << 20);
            size_t host_page_size{boost::interprocess::mapped_region::get_page_size()};
            data_size = ((data_size + host_page_size - 1) / host_page_size) * host_page_size;

            lmdb::options tgt_opts{};
            tgt_opts.read_only = false;
            tgt_opts.no_tls = false;
            tgt_opts.map_size = data_size;

            // Create target environment and open a rw transaction
            lmdb_tgt_env = lmdb::get_env(workdir.c_str(), tgt_opts);
            std::unique_ptr<lmdb::Transaction> tgt_txn{lmdb_tgt_env->begin_rw_transaction()};

            MDB_val key, data;
            // Loop source tables
            for (dbTableEntry table : tables) {
                if (table.id < 2 || !table.stat.ms_entries) continue;  // Skip reserved databases and empty tables

                if (table.name != "iTh2") continue;

                // Lookup TableConfig in known tables collection
                // If not found we have no way to determine which are the proper flags
                // required to open the table.
                std::optional<lmdb::TableConfig> config{db::table::get_config(table.name)};
                if (!config.has_value()) continue;

                std::cout << " Copying table " << table.name << std::endl;

                // Create table on destination with same configuration as origin
                bool src_is_dupsort{(config->flags & MDB_DUPSORT) == MDB_DUPSORT};
                auto src_table = src_txn->open(*config);
                auto tgt_table = tgt_txn->open(*config, MDB_CREATE);

                // Loop source and write into target
                int rc{src_table->get_first(&key, &data)};
                while (rc == MDB_SUCCESS) {
                    if (src_is_dupsort) {
                        size_t dups{0};
                        lmdb::err_handler(src_table->get_dcount(&dups));
                        do
                        {
                            //ByteView bv_key{ static_cast<uint8_t*>(key.mv_data), key.mv_size };
                            //ByteView bv_data{ static_cast<uint8_t*>(data.mv_data), data.mv_size };
                            //std::cout << to_hex(bv_key) << " " << to_hex(bv_data) << std::endl;
                            lmdb::err_handler(tgt_table->put_append(&key, &data));
                            if (!--dups) break;
                            lmdb::err_handler(src_table->get_next_dup(&key, &data));
                        } while (true);
                        rc = src_table->get_next_nodup(&key, &data);

                    } else {
                        lmdb::err_handler(tgt_table->put_append(&key, &data));
                        rc = src_table->get_next(&key, &data);
                    }
                }
                if (rc != MDB_NOTFOUND) {
                    lmdb::err_handler(rc);
                }
                // Close source and target
                src_table.reset();
                tgt_table.reset();
            }

            // Commit target transaction
            lmdb::err_handler(tgt_txn->commit());
            tgt_txn.reset();
            lmdb_tgt_env.reset();
        }

        std::cout << "Database compaction completed ..." << std::endl;
        // Do we have a valid compacted file on disk ?
        // replace source with target
        if (!bfs::exists(target)) {
            throw std::runtime_error("Can't locate compacted data.mdb");
        }

        // Close environment to release source file
        std::cout << "Closing origin db ..." << std::endl;
        lmdb_src_env->close();

        // Create a bak copy of source file
        if (keep) {
            std::cout << "Creating backup copy of origin db ..." << std::endl;
            bfs::path source_bak{bfs::path{datadir} / bfs::path{"data_mdb.bak"}};
            if (bfs::exists(source_bak)) {
                bfs::remove(source_bak);
            }
            bfs::rename(source, source_bak);
        }

        // Eventually replace original file
        if (bfs::exists(source)) {
            std::cout << "Deleting origin db ..." << std::endl;
            bfs::remove(source);
        }

        std::cout << "Replacing origin db with compacted ..." << std::endl;
        bfs::rename(target, source);

        std::cout << "All done !" << std::endl;

    } catch (const std::exception& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    lmdb_src_env.reset();
    lmdb_tgt_env.reset();
    return retvar;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    CLI::App app_main("Tests db interfaces.");

    std::string po_data_dir{""};     // Provided database path
    std::string po_work_dir{""};     // Provided work path
    std::string po_mapsize_str{""};  // Provided lmdb map size
    std::string po_table_name{""};   // Provided table name
    bool po_keep{false};             // Keep a copy of origin db (before compaction)
    bool po_copy{false};             // Enforce compaction by table copyying
    bool po_txids{false};            // For free list prints detail by transaction
    CLI::Range range32(1u, UINT32_MAX);

    app_main.add_option("--datadir", po_data_dir, "Path to directory for data.mdb", false);
    app_main.add_option("--lmdb.mapSize", po_mapsize_str, "Lmdb map size", true);

    auto& app_tables = *app_main.add_subcommand("tables", "List contained tables");

    auto& app_freelist = *app_main.add_subcommand("freelist", "List free pages");
    app_freelist.add_flag("--txids", po_txids, "List all transaction ids");

    auto& app_clear = *app_main.add_subcommand("clear", "Empties a named table");
    app_clear.add_option("--name", po_table_name, "Name of table to clear")->required();

    auto& app_drop = *app_main.add_subcommand("drop", "Drops a named table");
    app_drop.add_option("--name", po_table_name, "Name of table to drop")->required();

    auto& app_compact = *app_main.add_subcommand("compact", "Compacts an lmdb database");
    app_compact.add_option("--workdir", po_work_dir, "Working directory (must exist)", false)
        ->required()
        ->check(CLI::ExistingDirectory);
    app_compact.add_flag("--keep", po_keep, "Keep old file");
    app_compact.add_flag("--copy", po_copy, "Compact by copy");

    CLI11_PARSE(app_main, argc, argv);

    // If database path is provided check whether it is empty
    if (po_data_dir.empty()) {
        po_data_dir = silkworm::db::default_path();
    }
    bfs::path data_dir{po_data_dir};
    bfs::path data_file{po_data_dir / bfs::path{"data.mdb"}};
    if (!bfs::exists(data_file) || !bfs::is_regular_file(data_file)) {
        std::cerr << "\nNot found : " << data_file.string() << "\n"
                  << "Try --help for help" << std::endl;
        return -1;
    }

    std::optional<uint64_t> lmdb_mapSize{parse_size(po_mapsize_str)};
    uint64_t lmdb_fileSize{bfs::file_size(data_file)};

    // Do not accept mapSize below filesize
    if (!lmdb_mapSize.has_value()) {
        lmdb_mapSize = lmdb_fileSize;
    } else {
        *lmdb_mapSize = std::max(*lmdb_mapSize, lmdb_fileSize);
    }

    // Adjust mapSize to a multiple of page_size
    size_t host_page_size{boost::interprocess::mapped_region::get_page_size()};
    *lmdb_mapSize = ((*lmdb_mapSize + host_page_size - 1) / host_page_size) * host_page_size;

    if (app_tables) {
        return do_tables(po_data_dir, lmdb_fileSize, lmdb_mapSize);
    } else if (app_freelist) {
        return do_freelist(po_data_dir, lmdb_mapSize, po_txids);
    } else if (app_clear) {
        return do_drop(po_data_dir, lmdb_mapSize, po_table_name, false);
    } else if (app_drop) {
        return do_drop(po_data_dir, lmdb_mapSize, po_table_name, true);
    } else if (app_compact) {
        return do_compact(po_data_dir, lmdb_mapSize, po_work_dir, po_keep, po_copy);
    } else {
        std::cerr << "No command specified" << std::endl;
    }

    return -1;
}
