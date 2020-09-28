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
#include <csignal>
#include <iostream>
#include <regex>
#include <silkworm/chain/config.hpp>
#include <silkworm/db/bucket.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/types/block.hpp>
#include <string>

namespace bfs = boost::filesystem;
using namespace silkworm;

bool shouldStop{false};
int errorCode{0};

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

int drop_table(std::string datadir, std::optional<uint64_t> mapsize, std::string tablename, bool del) {

    int retvar{0};
    bool should_commit{false};
    std::shared_ptr<db::lmdb::Environment> lmdb_env{ nullptr };  // Main lmdb environment
    std::unique_ptr<db::lmdb::Transaction> lmdb_txn{ nullptr };  // Main lmdb transaction
    std::unique_ptr<db::lmdb::Table> lmdb_tbl{nullptr};          // Table name to be cleared

    try {
        // Open db and start a rw transaction
        db::lmdb::options opts{};
        if (mapsize.has_value()) opts.map_size = *mapsize;
        lmdb_env = db::get_env(datadir.c_str(), opts, /* forwriting=*/true);
        lmdb_txn = lmdb_env->begin_rw_transaction();
        lmdb_tbl = lmdb_txn->open(tablename.c_str());

        size_t rcount{0};
        lmdb_tbl->get_rcount(&rcount);
        if (!del && !rcount) {
            std::cout << "\nTable " << tablename << " is already empty." << std::endl;
        }
        else {
            int rc{0};
            if (!del) {
                std::cout << "\nEmptying table " << tablename << " (" << rcount << " records)" << std::endl;
                rc = lmdb_tbl->clear();

            } else {
                std::cout << "\nDeleting table " << tablename << " (" << rcount << " records)" << std::endl;
                rc = lmdb_tbl->drop();
            }
            if (!rc) {
                should_commit = true;
            }
            else
            {
                throw std::runtime_error(mdb_strerror(rc));
            }
        }
        lmdb_tbl->close();

    }
    catch (db::lmdb::exception& ex) {
        // This handles specific lmdb errors
        std::cout << ex.err() << " " << ex.what() << std::endl;
        retvar = -1;
    }
    catch (std::runtime_error& ex) {
        // This handles runtime logic errors
        // eg. trying to open two rw txns
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    int rc{0};


    if (lmdb_txn) {
        if (!retvar && should_commit) {
            std::cout << "Committing ... " << std::endl;
            rc = lmdb_txn->commit();
            if (rc) {
                std::cerr << "Unable to commit : " << mdb_strerror(rc) << std::endl;
                lmdb_txn->abort();
                retvar = -1;
            } else {
                std::cout << "Success !" << std::endl;
            }
        } else {
            lmdb_txn->abort();
        }
    }
    if (lmdb_env) {
        lmdb_env->close();
    }

    return retvar;

}

int list_tables(std::string datadir, std::optional<uint64_t> mapsize) {

    int retvar{0};
    std::shared_ptr<db::lmdb::Environment> lmdb_env{ nullptr };  // Main lmdb environment
    std::unique_ptr<db::lmdb::Transaction> lmdb_txn{ nullptr };  // Main lmdb transaction

    try {
        // Open db and start transaction
        db::lmdb::options opts{};
        if (mapsize.has_value()) opts.map_size = *mapsize;
        lmdb_env = db::get_env(datadir.c_str(), opts, /* forwriting=*/false);
        lmdb_txn = lmdb_env->begin_ro_transaction();

        unsigned int id{0};
        MDB_envinfo i;
        MDB_stat s;
        MDB_val key, data;

        lmdb_env->get_info(&i);

        // A list of tables stored into the database
        auto unnamed = lmdb_txn->open(0);

        unnamed->get_stat(&s);
        std::cout << "\nDatabase contains " << s.ms_entries << " named tables\n" << std::endl;

        std::cout << std::right << std::setw(4) << std::setfill(' ') << "Dbi"
                  << " " << std::left << std::setw(30) << std::setfill(' ') << "Table name"
                  << " " << std::right << std::setw(10) << std::setfill(' ') << "Records" << std::endl;
        std::cout << std::right << std::setw(4) << std::setfill('-') << ""
                  << " " << std::left << std::setw(30) << std::setfill('-') << ""
                  << " " << std::right << std::setw(10) << std::setfill('-') << "" << std::endl;

        int rc{unnamed->get_first(&key, &data)};
        while (!shouldStop && rc == MDB_SUCCESS) {
            id++;
            std::string_view v{ static_cast<char*>(key.mv_data), key.mv_size };
            size_t rcount{0};
            auto b = lmdb_txn->open(v.data());
            b->get_rcount(&rcount);
            b->close();

            std::cout << std::right << std::setw(4) << std::setfill(' ') << id
                << " " << std::left << std::setw(30) << std::setfill(' ') << v
                << " " << std::right << std::setw(10) << std::setfill(' ') << rcount << std::endl;

            rc = unnamed->get_next(&key, &data);
        }
        std::cout << std::endl;
        unnamed->close();
    }
    catch (db::lmdb::exception& ex) {
        // This handles specific lmdb errors
        std::cout << ex.err() << " " << ex.what() << std::endl;
        retvar = -1;
    }
    catch (std::runtime_error& ex) {
        // This handles runtime logic errors
        // eg. trying to open two rw txns
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    if (lmdb_txn) {
        lmdb_txn->abort();
    }
    if (lmdb_env) {
        lmdb_env->close();
    }

    return retvar;

}

int main(int argc, char* argv[]) {

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    CLI::App app("Tests db interfaces.");


    std::string po_data_dir{silkworm::db::default_path()};  // Default database path
    std::string po_mapsize_str{"0"};                        // Default lmdb map size
    std::string po_table_name{""};                          // Default table name
    bool po_debug{false};                                   // Might be ignored
    CLI::Range range32(1u, UINT32_MAX);

    // Check whether or not default db_path exists and has some files in it
    bfs::path db_path(po_data_dir);
    CLI::Option* db_path_set =
        app.add_option("--datadir", po_data_dir, "Path to chain db", true)->check(CLI::ExistingDirectory);
    if (!bfs::exists(db_path) || !bfs::is_directory(db_path) || db_path.empty()) {
        db_path_set->required();
    }
    app.add_option("--lmdb.mapSize", po_mapsize_str, "Lmdb map size", true);

    auto& app_tables = *app.add_subcommand("tables", "List contained tables");

    auto& app_clear = *app.add_subcommand("clear", "Empties a named table");
    app_clear.add_flag("--name", po_table_name, "Name of table")->required();

    auto& app_drop = *app.add_subcommand("drop", "Drops a named table");
    app_drop.add_flag("--name", po_table_name, "Name of table")->required();

    CLI11_PARSE(app, argc, argv);

    std::optional<uint64_t> lmdb_mapSize = parse_size(po_mapsize_str);
    if (!lmdb_mapSize) {
        std::cout << "Invalid map size" << std::endl;
        return -1;
    }

    // If database path is provided (and has passed CLI::ExistingDirectory validator
    // check whether it is empty
    db_path = bfs::path(po_data_dir);
    if (db_path.empty()) {
        std::cerr << "Provided --datadir [" << po_data_dir << "] is an empty directory" << std::endl
                  << "Try --help for help" << std::endl;
        return -1;
    }

    if (app_tables) {
        return list_tables(po_data_dir, lmdb_mapSize);
    } else if (app_clear) {
        return drop_table(po_data_dir, lmdb_mapSize, po_table_name, false);
    } else if (app_drop) {
        return drop_table(po_data_dir, lmdb_mapSize, po_table_name, true);
    } else {
        std::cerr << "No command specified" << std::endl;
    }

    return -1;
}
