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
#include <boost/interprocess/mapped_region.hpp>
#include <csignal>
#include <iostream>
#include <regex>
#include <silkworm/chain/config.hpp>
#include <silkworm/db/chaindb.hpp>
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
    std::size_t freelist{};
    MDB_stat stat{};
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
        return {};
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
        return {};
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

std::vector<dbTableEntry> get_tables(std::unique_ptr<lmdb::Transaction>& tx) {
    std::vector<dbTableEntry> ret{};
    MDB_val key, data;

    auto unnamed = tx->open(lmdb::FREE_DBI);
    ret.push_back({unnamed->get_dbi(), unnamed->get_name()});
    lmdb::err_handler(unnamed->get_stat(&ret.back().stat));

    unnamed.reset();
    unnamed = tx->open(lmdb::MAIN_DBI);  // Opens unnamed table (every lmdb has one)
    ret.push_back({ unnamed->get_dbi(), unnamed->get_name() });
    lmdb::err_handler(unnamed->get_stat(&ret.back().stat));
    if (ret.back().stat.ms_entries) {

        lmdb::err_handler(unnamed->get_first(&key, &data));
        while (!shouldStop) {

            if (data.mv_size < sizeof(size_t)) {
                lmdb::err_handler(MDB_INVALID);
            }

            auto p_data = static_cast<uint8_t*>(data.mv_data);
            auto named = tx->open({(const char*)key.mv_data});
            ret.push_back(
                {named->get_dbi(), named->get_name(),
                 (sizeof(size_t) == 8 ? boost::endian::load_big_u64(p_data) : boost::endian::load_big_u32(p_data))});
            lmdb::err_handler(named->get_stat(&ret.back().stat));
            int rc{unnamed->get_next(&key, &data)};
            if (rc == MDB_NOTFOUND) break;
            lmdb::err_handler(rc);
        }
    }
    return ret;
}

int do_tables(std::string datadir, size_t file_size, std::optional<uint64_t> mapsize) {
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
        std::cout << "\n Transaction id " << lmdb_txn->get_id() << std::endl;

        std::vector<dbTableEntry> entries{get_tables(lmdb_txn)};
        size_t items_size{0};
        size_t items_free{0};
        std::cout << "\n Database contains " << entries.size() << " tables\n" << std::endl;
        if (entries.size()) {
            std::cout << std::right << std::setw(4) << std::setfill(' ') << "Dbi"
                      << " " << std::left << std::setw(30) << std::setfill(' ') << "Table name"
                      << " " << std::right << std::setw(10) << std::setfill(' ') << "Records"
                      << " " << std::right << std::setw(6) << std::setfill(' ') << "Depth"
                      << " " << std::right << std::setw(12) << std::setfill(' ') << "Size"
                      << " " << std::right << std::setw(12) << std::setfill(' ') << "Free" << std::endl;

            std::cout << std::right << std::setw(4) << std::setfill('-') << ""
                      << " " << std::left << std::setw(30) << std::setfill('-') << ""
                      << " " << std::right << std::setw(10) << std::setfill('-') << ""
                      << " " << std::right << std::setw(6) << std::setfill('-') << ""
                      << " " << std::right << std::setw(12) << std::setfill('-') << ""
                      << " " << std::right << std::setw(12) << std::setfill('-') << "" << std::endl;

            for (dbTableEntry item : entries) {
                size_t item_size{item.stat.ms_psize *
                                 (item.stat.ms_leaf_pages + item.stat.ms_branch_pages + item.stat.ms_overflow_pages)};
                items_size += item_size;
                items_free += item.freelist;

                std::cout << std::right << std::setw(4) << std::setfill(' ') << item.id << " " << std::left
                          << std::setw(30) << std::setfill(' ') << item.name << " " << std::right << std::setw(10)
                          << std::setfill(' ') << item.stat.ms_entries << " " << std::right << std::setw(6)
                          << std::setfill(' ') << item.stat.ms_depth << " " << std::right << std::setw(12)
                          << std::setfill(' ') << item_size << " " << std::right << std::setw(12) << std::setfill(' ')
                          << item.freelist << std::endl;
            }
        }

        std::cout << "\n Size of file on disk : " << std::right << std::setw(12) << std::setfill(' ') << file_size
                  << std::endl;
        std::cout << " Size of data in file : " << std::right << std::setw(12) << std::setfill(' ') << items_size
                  << std::endl;
        std::cout << " Total free list      : " << std::right << std::setw(12) << std::setfill(' ') << items_free
                  << std::endl;
        std::cout << " Free space available : " << std::right << std::setw(12) << std::setfill(' ')
                  << (file_size - items_size) << std::endl;

    } catch (lmdb::exception& ex) {
        // This handles specific lmdb errors
        std::cout << ex.err() << " " << ex.what() << std::endl;
        retvar = -1;
    } catch (std::runtime_error& ex) {
        // This handles runtime logic errors
        // eg. trying to open two rw txns
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

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
            std::unique_ptr<lmdb::Transaction> src_txn{ lmdb_src_env->begin_ro_transaction() };
            auto tables = get_tables(src_txn);
            size_t data_size{ 0 };

            // Compute size of data we need to copy
            for (dbTableEntry table : tables) {
                if (table.id < 2) continue;  // Dont account data from reserved databases
                data_size += table.stat.ms_psize *
                             (table.stat.ms_leaf_pages + table.stat.ms_branch_pages + table.stat.ms_overflow_pages);
            }

            // Round up data size to 1MB (1ull << 20)
            data_size = ((data_size + (1ull << 20) - 1) / (1ull << 20)) * (1ull << 20);
            lmdb::options tgt_opts{};
            tgt_opts.read_only = false;
            tgt_opts.map_size = data_size;

            // Create target environment and open a rw transaction
            lmdb_tgt_env = lmdb::get_env(workdir.c_str(), tgt_opts);
            std::unique_ptr<lmdb::Transaction> tgt_txn{ lmdb_tgt_env->begin_rw_transaction() };

            MDB_val key, data;
            // Loop source tables
            for (dbTableEntry table : tables) {
                if (table.id < 2 || !table.stat.ms_entries) continue;  // Skip reserved databases and empty tables

                // Create table on destination
                std::cout << " Copying table " << table.name << std::endl;
                auto src_table = src_txn->open({table.name.c_str()});
                auto tgt_table = tgt_txn->open({table.name.c_str()}, MDB_CREATE);

                // Loop source and write into target
                lmdb::err_handler(src_table->get_first(&key, &data));
                do
                {
                    lmdb::err_handler(tgt_table->put_append(&key, &data));
                } while (!src_table->get_next(&key, &data));

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
    CLI::Range range32(1u, UINT32_MAX);

    app_main.add_option("--datadir", po_data_dir, "Path to directory for data.mdb", false);
    app_main.add_option("--lmdb.mapSize", po_mapsize_str, "Lmdb map size", true);

    auto& app_tables = *app_main.add_subcommand("tables", "List contained tables");

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

    std::optional<uint64_t> lmdb_mapSize;
    std::size_t lmdb_fileSize{bfs::file_size(data_file)};
    if (po_mapsize_str.empty()) {
        lmdb_mapSize = lmdb_fileSize;
    } else {
        lmdb_mapSize = parse_size(po_mapsize_str);
    }
    if (!lmdb_mapSize.has_value()) {
        std::cout << "Invalid map size" << std::endl;
        return -1;
    }

    // Adjust mapSize to a multiple of page_size
    size_t host_page_size{boost::interprocess::mapped_region::get_page_size()};
    *lmdb_mapSize = ((*lmdb_mapSize + host_page_size - 1) / host_page_size) * host_page_size;

    if (app_tables) {
        return do_tables(po_data_dir, lmdb_fileSize, lmdb_mapSize);
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
