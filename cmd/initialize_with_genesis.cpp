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

#include <iostream>

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/filesystem.hpp>

#include <fstream>
#include <json/json.h>

#include <silkworm/common/log.hpp>
#include <silkworm/common/base.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/common/chain_genesis.hpp>

using namespace silkworm;

constexpr uint8_t genesis_body[] = {195, 128, 128, 192};
constexpr uint8_t genesis_receipts[] = {246};

uint64_t get_balance_from_alloc(std::string balance_field) {
    // Balance in genesis can be either in decimal format (E.G 10000000...)
    // Or Hex format (0x25f749b....) 
}
int main(int argc, char* argv[]) {
    namespace fs = boost::filesystem;
    int chain_id{-1};
    CLI::App app{"Generates Tc Hashes => BlockNumber mapping in database"};

    std::string out;
    std::string genesis;
    app.add_option("--out", out, "Path to the newly created chaindata", true);

    app.add_option("--genesis", genesis, "Path to the genesis json file", true)
        ->check(CLI::ExistingDirectory);

    app.add_option("--chainid", chain_id, "Specify id of the chain to generate");

    CLI11_PARSE(app, argc, argv);

    // Check flags
    if (fs::exists(out)) {
        SILKWORM_LOG(LogLevel::Error) << out << " already exist." << std::endl;
        return -1;
    }

    if (!fs::exists(genesis) && chain_id <= 0) {
        SILKWORM_LOG(LogLevel::Error) << "genesis was not found." << std::endl;
        return -1;
    }
    // We create the chaindata directory
    fs::create_directories(out);

    // We Initialize the database and open it
    lmdb::DatabaseConfig db_config{out};
    db_config.set_readonly(false);
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
    std::unique_ptr<lmdb::Transaction> txn{env->begin_rw_transaction()};
    // We create all tables
    db::table::create_all(*txn);
    // Read genesis json file
    Json::Value genesis_json;

    if (chain_id <= 0) {
        std::ifstream in(genesis.data(),std::ios::binary);
        in >> genesis_json;
    } else {
        Json::CharReaderBuilder builder;
        Json::CharReader* reader = builder.newCharReader();
        std::string errors;
        std::string genesis;
        switch (chain_id) {
            case 1:
                genesis = kMainnetGenesis;
                break;
            default:
                SILKWORM_LOG(LogLevel::Error) << "chain id: " << chain_id << " does not exist." << std::endl;
                return -1;
        }
        bool success{reader->parse(
            genesis.c_str(),
            genesis.c_str() + genesis.size(),
            &genesis_json,
            &errors
        )};
        delete reader;
        if (!success) {
            SILKWORM_LOG(LogLevel::Error) << "Failed to parse the JSON, errors:" << std::endl;
            SILKWORM_LOG(LogLevel::Error) << errors << std::endl;
            return -1;
        }
    }
    // Filling account + constructing genesis root hash
    auto alloc_json{genesis_json["alloc"]};
    std::map<evmc::bytes32, Bytes> account_rlp;
    auto plainstate_table{txn->open(db::table::kPlainState)};
    for (Json::ValueIterator itr = alloc_json.begin(); itr != alloc_json.end(); itr++) {
        std::cout << *itr.asString() << std::endl;
        //ethash::hash256 hash{keccak256(full_view(address))};
        //account_rlp[to_bytes32(full_view(hash.bytes))] = account.rlp(kEmptyRoot);
    }

   /* auto it{account_rlp.cbegin()};
    trie::HashBuilder hb{full_view(it->first), it->second};
    for (++it; it != account_rlp.cend(); ++it) {
        hb.add(full_view(it->first), it->second);
    }

    auto root_hash{hb.root_hash()};*/
    // Inserting Genesis Header
    // Inserting Genesis Body
    // Inserting Genesis Receipts

    /*
    *   Initialization will do the following:
    *       * Writting allocations accounts
    *       * Changesets
    *       * Writting genesis block, headers and receipts.
    */

}
