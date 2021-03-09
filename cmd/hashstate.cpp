/*
   Copyright 2021 The Silkworm Authors

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
#include <iostream>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>

using namespace silkworm;
namespace fs = boost::filesystem;

enum Operation {
    HashAccount,
    HashStorage,
    Code
};

void promote_clean(lmdb::Transaction * txn, std::string etl_path, Operation operation) {
    auto source_table{operation != Code ? 
        txn->open(db::table::kPlainState) : txn->open(db::table::kPlainContractCode)
    };
    MDB_val mdb_key{db::to_mdb_val(Bytes(8, '\0'))};
    MDB_val mdb_data;
    int rc{source_table->seek(&mdb_key, &mdb_data)};
    fs::create_directories(etl_path);
    etl::Collector collector(etl_path.c_str(), 512 * kMebi);
    while (!rc) { /* Loop as long as we have no errors*/

        // Ensure the reached block number is in proper sequence
        Bytes mdb_key_as_bytes{static_cast<uint8_t*>(mdb_key.mv_data), mdb_key.mv_size};
        Bytes mdb_value_as_bytes{static_cast<uint8_t*>(mdb_data.mv_data), mdb_data.mv_size};
        Bytes new_key;
        switch (operation) {
            case HashAccount:
                new_key = Bytes(keccak256(mdb_key_as_bytes).bytes, kHashLength);
                break;
            case HashStorage:
                new_key = Bytes('\0', kHashLength*2+db::kIncarnationLength);
                std::memcpy(&new_key[0], keccak256(mdb_key_as_bytes.substr(0, kAddressLength)).bytes, kHashLength);
                std::memcpy(&new_key[kHashLength], &mdb_key_as_bytes[kAddressLength], db::kIncarnationLength);
                std::memcpy(&new_key[kHashLength + db::kIncarnationLength], keccak256(mdb_key_as_bytes.substr(kAddressLength + db::kIncarnationLength)).bytes, kHashLength);
                break;
            case Code:
                new_key = Bytes('\0', kHashLength+db::kIncarnationLength);
                std::memcpy(&new_key[0], keccak256(mdb_key_as_bytes.substr(0, kAddressLength)).bytes, kHashLength);
                std::memcpy(&new_key[kHashLength], &mdb_key_as_bytes[kAddressLength], db::kIncarnationLength);
                break;
        }
        etl::Entry entry{new_key, mdb_value_as_bytes};
        collector.collect(entry);
        rc = source_table->get_next(&mdb_key, &mdb_data);
    }

    if (rc && rc != MDB_NOTFOUND) { /* MDB_NOTFOUND is not actually an error rather eof */
        lmdb::err_handler(rc);
    }

    SILKWORM_LOG(LogInfo) << "Started Loading" << std::endl;

    /*
    * If we're on first sync then we shouldn't have any records in target
    * table. For this reason we can apply MDB_APPEND to load as
    * collector (with no transform) ensures collected entries
    * are already sorted. If instead target table contains already
    * some data the only option is to load in upsert mode as we
    * cannot guarantee keys are sorted amongst different calls
    * of this stage
    */
    switch (operation) {
        case HashAccount:
                collector.load(txn->open(db::table::kHashedAccounts, MDB_CREATE).get(), nullptr, MDB_APPEND, /* log_every_percent = */ 10);
                break;
        case HashStorage:
                collector.load(txn->open(db::table::kHashedStorage, MDB_CREATE).get(), nullptr, MDB_APPENDDUP, /* log_every_percent = */ 10);
                break;
        case Code:
                collector.load(txn->open(db::table::kContractCode, MDB_CREATE).get(), nullptr, MDB_APPEND, /* log_every_percent = */ 10);
                break;
    }
    // Update progress height with last processed block
    db::stages::set_stage_progress(*txn, db::stages::kHashStateKey, db::stages::get_stage_progress(*txn, db::stages::kExecutionKey));
    lmdb::err_handler(txn->commit());
}

void promote(lmdb::Transaction *, std::string , Operation ) {
    // TODO
}

int main(int argc, char* argv[]) {
    CLI::App app{"Generates Hashed state"};

    std::string db_path{db::default_path()};
    bool full, incrementally;
    app.add_option("-d,--datadir", db_path, "Path to a database populated by Turbo-Geth", true)
        ->check(CLI::ExistingDirectory);

    app.add_flag("--full", full, "Start making lookups from block 0");
    app.add_flag("--increment", incrementally, "Use incremental method");
    CLI11_PARSE(app, argc, argv);


    // Check data.mdb exists in provided directory
    boost::filesystem::path db_file{boost::filesystem::path(db_path) / boost::filesystem::path("data.mdb")};
    if (!boost::filesystem::exists(db_file)) {
        SILKWORM_LOG(LogError) << "Can't find a valid TG data file in " << db_path << std::endl;
        return -1;
    }
    fs::path datadir(db_path);
    fs::path etl_path(datadir.parent_path() / fs::path("etl-temp"));

    lmdb::DatabaseConfig db_config{db_path};
    db_config.set_readonly(false);
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
    std::unique_ptr<lmdb::Transaction> txn{env->begin_rw_transaction()};

    try {
        uint64_t last_processed_block_number;
        if (full) {
            txn->open(db::table::kHashedAccounts)->clear();
            txn->open(db::table::kHashedStorage)->clear();
            txn->open(db::table::kContractCode)->clear();
            last_processed_block_number = 0;
        } else {
            last_processed_block_number = db::stages::get_stage_progress(*txn, db::stages::kHashStateKey);
        }
        if (last_processed_block_number != 0 || incrementally) {
            promote(txn.get(), etl_path.string(), HashAccount);
            promote(txn.get(), etl_path.string(), HashStorage);
            promote(txn.get(), etl_path.string(), Code);
        } else {
            promote_clean(txn.get(), etl_path.string(), HashAccount);
            promote_clean(txn.get(), etl_path.string(), HashStorage);
            promote_clean(txn.get(), etl_path.string(), Code);
        }
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogError) << ex.what() << std::endl;
        return -5;
    }
}
