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
#include <silkworm/chain/config.hpp>
#include <silkworm/db/bucket.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/types/block.hpp>
#include <regex>
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
    std::regex pattern{ "^([0-9]{1,})([\\ ]{0,})?(B|KB|MB|GB|TB|EB)?$" };
    std::smatch matches;
    if (!std::regex_search(strsize, matches, pattern, std::regex_constants::match_default)) {
        return {};
    };

    uint64_t number{ std::strtoull(matches[1].str().c_str(), nullptr, 10) };

    if (matches[3].length() == 0) {
        return { number };
    }
    std::string suffix = matches[3].str();
    if (suffix == "B") {
        return { number };
    }
    else if (suffix == "KB") {
        return { number * (1ull << 10) };
    }
    else if (suffix == "MB") {
        return { number * (1ull << 20) };
    }
    else if (suffix == "GB") {
        return { number * (1ull << 30) };
    }
    else if (suffix == "TB") {
        return { number * (1ull << 40) };
    }
    else if (suffix == "EB") {
        return { number * (1ull << 50) };
    }
    else {
        return {};
    }
}

int main(int argc, char* argv[]) {
    CLI::App app("Tests db interfaces.");

    std::string po_data_dir{silkworm::db::default_path()};  // Default database path
    std::string po_mapsize_str{"0"};                        // Default lmdb map size
    bool po_debug{false};                                   // Might be ignored
    CLI::Range range32(1u, UINT32_MAX);

    // Check whether or not default db_path exists and
    // has some files in it
    bfs::path db_path(po_data_dir);
    CLI::Option* db_path_set =
        app.add_option("--datadir", po_data_dir, "Path to chain db", true)->check(CLI::ExistingDirectory);
    if (!bfs::exists(db_path) || !bfs::is_directory(db_path) || db_path.empty()) {
        db_path_set->required();
    }

    app.add_flag("-d,--debug", po_debug, "May be ignored.");
    app.add_option("--lmdb.mapSize", po_mapsize_str, "Lmdb map size", true);

    CLI11_PARSE(app, argc, argv);
    std::optional<uint64_t>lmdb_mapSize = parse_size(po_mapsize_str);
    if (!lmdb_mapSize) {
        std::cout << "Invalid map size" << std::endl;
        return -1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // If database path is provided (and has passed CLI::ExistingDirectory validator
    // check whether it is empty
    db_path = bfs::path(po_data_dir);
    if (db_path.empty()) {
        std::cerr << "Provided --datadir [" << po_data_dir << "] is an empty directory" << std::endl
                  << "Try --help for help" << std::endl;
        return -1;
    }

    std::shared_ptr<db::lmdb::Environment> lmdb_env{nullptr};  // Main lmdb environment
    std::unique_ptr<db::lmdb::Transaction> lmdb_txn{nullptr};  // Main lmdb transaction

    try {

        // Open db and start transaction
        db::lmdb::options opts{};
        if (*lmdb_mapSize) opts.map_size = *lmdb_mapSize;
        lmdb_env = db::get_env(po_data_dir.c_str(), opts, /* forwriting=*/true);
        std::cout << "Database is " << (lmdb_env->is_opened() ? "" : "NOT ") << "opened" << std::endl;
        lmdb_txn = lmdb_env->begin_rw_transaction();

        MDB_envinfo i;
        MDB_stat s;
        MDB_val key, data;

        lmdb_env->get_info(&i);

        std::cout << "Database page size : " << i.me_mapsize << std::endl;

        // A list of tables stored into the database
        auto unnamed = lmdb_txn->open(0);

        unnamed->get_stat(&s);
        std::cout << "Database contains " << s.ms_entries << " named tables" << std::endl;
        int rc{unnamed->get_first(&key, &data)};
        while (!shouldStop && rc == MDB_SUCCESS) {
            std::string_view v{static_cast<char*>(key.mv_data), key.mv_size};
            std::cout << "Bucket " << v << " with ";
            {
                size_t rcount{0};
                auto b = lmdb_txn->open(v.data());
                b->get_rcount(&rcount);
                std::cout << rcount << " record(s)\n";
                b->close();
            }
            rc = unnamed->get_next(&key, &data);
        }
        std::cout << "\n" << std::endl;
        std::cout << "Independent cursor navigation\n";

        // Independent cursor navigation sample
        rc = unnamed->get_first(&key, &data);
        MDB_val key_rev, data_rev;
        auto unnamed_rev = lmdb_txn->open(0);
        rc = unnamed_rev->get_last(&key_rev, &data_rev);
        while (!shouldStop && rc == MDB_SUCCESS) {
            std::string_view v{ static_cast<char*>(key.mv_data), key.mv_size };
            std::string_view v_rev{ static_cast<char*>(key_rev.mv_data), key_rev.mv_size };
            std::cout << "Cursor 1 Key " << v << "  Cursor 2 Key " << v_rev << "\n";
            rc = unnamed->get_next(&key, &data);
            rc = unnamed_rev->get_prev(&key_rev, &data_rev);
        }

        std::cout << "\n" << std::endl;
        unnamed->close();
        unnamed_rev->close();

    } catch (db::lmdb::exception& ex) {
        // This handles specific lmdb errors
        std::cout << ex.err() << " " << ex.what() << std::endl;
    } catch (std::runtime_error& ex) {
        // This handles runtime ligic errors
        // eg. trying to open two rw txns
        std::cout << ex.what() << std::endl;
    }

    if (lmdb_txn) lmdb_txn->abort();
    if (lmdb_env) {
        lmdb_env->close();
        std::cout << "Database is " << (lmdb_env->is_opened() ? "" : "NOT ") << "opened" << std::endl;
    }

    return 0;
}
