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
#include <stdlib.h>
#include <fstream>

#include <silkworm/common/log.hpp>
#include <silkworm/trie/hash_builder.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/common/base.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/common/chain_genesis.hpp>
#include <nlohmann/json.hpp>

using namespace silkworm;

constexpr uint8_t genesis_body[] = {195, 128, 128, 192};
constexpr uint8_t genesis_receipts[] = {246};
constexpr evmc::bytes32 kNullOmmers{0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32};

static void check_rlp_err(rlp::DecodingResult err) {
    if (err != rlp::DecodingResult::kOk) {
        throw err;
    }
}

static intx::uint256 convert_string_to_uint256(std::string const& str) {
    intx::uint256 res{0};
    for(size_t i = 0; i < str.size(); i++) {
        auto current_digit{str.at(i) - '0'};
        res += current_digit;
        res *= 10;
    }
    return res/10;
}

static bool is_hex(std::string const& s) {
  return s.compare(0, 2, "0x") == 0
      && s.size() > 2
      && s.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos;
}

static uint64_t get_uint_from_field(std::string const& field) {
    int form = is_hex(field)? 16 : 10;
    uint64_t res = strtoull(field.c_str(), nullptr, form);
    if (errno == EINVAL)
    {
        SILKWORM_LOG(LogLevel::Error) << field << " not a valid number." << std::endl;
        throw;
    }
    else if (errno == ERANGE)
    {
        SILKWORM_LOG(LogLevel::Error) << field << " must be uint64" << std::endl;
        throw;
    }
    return res;
}

int main(int argc, char* argv[]) {
    namespace fs = boost::filesystem;
    int chain_id{-1};
    CLI::App app{"Initializes database with genesis json file"};

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
    nlohmann::json genesis_json;

    if (chain_id <= 0) {
        std::ifstream t(genesis.data());
        std::string str((std::istreambuf_iterator<char>(t)),
                        std::istreambuf_iterator<char>());
        genesis_json = nlohmann::json::parse(str);
    } else {
        switch (chain_id) {
            case 1:
                genesis_json = nlohmann::json::parse(kMainnetGenesis);
                break;
            case 4:
                genesis_json = nlohmann::json::parse(kRinkebyGenesis);
                break;
            case 5:
                genesis_json = nlohmann::json::parse(kGoerliGenesis);
                break;
            default:
                SILKWORM_LOG(LogLevel::Error) << "chain id: " << chain_id << " does not exist." << std::endl;
                return -1;
        }
    }
    if (!genesis_json.contains("difficulty") || !genesis_json.contains("nonce") ||
        !genesis_json.contains("gasLimit") || !genesis_json.contains("timestamp") || 
        !genesis_json.contains("extraData")) {
        SILKWORM_LOG(LogLevel::Error) << "Incomplete Genesis File" << std::endl;
        return -1;
    }
    auto block_number{Bytes(8, '\0')};
    evmc::bytes32 root_hash;
    if (genesis_json.contains("alloc")) {
        // Filling account + constructing genesis root hash
        auto alloc_json{genesis_json["alloc"]};
        std::map<evmc::bytes32, Bytes> account_rlp;
        // Tables used
        auto plainstate_table{txn->open(db::table::kPlainState)};
        auto account_changeset_table{txn->open(db::table::kPlainAccountChangeSet)};
        std::unique_ptr<trie::HashBuilder> hb;
        // Iterate over allocs
        for (auto& [key, value] : alloc_json.items()) {
            auto address_bytes{from_hex(key)};
            if (address_bytes == std::nullopt) {
                SILKWORM_LOG(LogLevel::Error) << "Cannot decode allocs from genesis" << std::endl;
                return -1;
            }
            auto balance_str{value["balance"].get<std::string>()};
            intx::uint256 balance;        
            Account account;
            if (is_hex(balance_str)) {
                auto balance_bytes{from_hex(balance_str)};
                auto [balance_decoded, err]{rlp::read_uint256(*balance_bytes, /*allow_leading_zeros=*/true)};
                check_rlp_err(err);
                balance = balance_decoded;
            } else {
                balance = convert_string_to_uint256(balance_str);
            }
            account.balance = balance;
            // Make the account
            account_changeset_table->put(block_number, *address_bytes);
            plainstate_table->put(*address_bytes, account.encode_for_storage(true));
            // Fills hash builder
            auto hash{keccak256(*address_bytes)};
            if (hb == nullptr) {
                hb = std::make_unique<trie::HashBuilder>(full_view(hash.bytes), account.rlp(kEmptyRoot));
            } else {
                hb->add(full_view(hash.bytes), account.rlp(kEmptyRoot));
            }
        }
        root_hash = hb->root_hash();
    } else {
        root_hash = kEmptyRoot;
    }

    // Fill Header
    BlockHeader header;
    header.ommers_hash = kNullOmmers;
    header.state_root = root_hash;
    header.transactions_root = kEmptyRoot;
    header.receipts_root = kEmptyRoot;
    intx::uint256 difficulty;
    auto difficulty_str{genesis_json["difficulty"].get<std::string>()};
    Bytes difficulty_bytes;
    if (is_hex(difficulty_str)) {
        difficulty_bytes = *from_hex(difficulty_str);
        auto [difficulty_decoded, err]{rlp::read_uint256(difficulty_bytes, /*allow_leading_zeros=*/true)};
        check_rlp_err(err);
        difficulty = difficulty_decoded;
    } else {
        difficulty = convert_string_to_uint256(difficulty_str);
    }
    header.difficulty = difficulty;
    auto gas_limit{genesis_json["gasLimit"].get<std::string>()};
    header.gas_limit = get_uint_from_field(gas_limit);
    auto timestamp{genesis_json["timestamp"].get<std::string>()};
    header.timestamp = get_uint_from_field(timestamp);
    auto extra_data_str{genesis_json["extraData"].get<std::string>()};
    header.extra_data = from_hex(extra_data_str).value();
    auto nonce_str{genesis_json["nonce"].get<std::string>()};
    auto nonce_bytes{from_hex(nonce_str)};
    auto diff_nonce_size(8-nonce_bytes->size());
    for (size_t i = 0; i < nonce_bytes->size(); i++) 
        header.nonce[i+diff_nonce_size] = nonce_bytes->at(i+diff_nonce_size);
    // Write header
    auto blockhash{header.hash()};
    Bytes rlp_header;
    rlp::encode(rlp_header, header);
    Bytes key(8 + kHashLength, '\0');
    std::memcpy(&key[8], blockhash.bytes, kHashLength);
    txn->open(db::table::kHeaders)->put(key, rlp_header);
    txn->open(db::table::kCanonicalHashes)->put(block_number, full_view(blockhash.bytes));
    // Write body
    txn->open(db::table::kBlockBodies)->put(key, Bytes(genesis_body, 3));
    txn->open(db::table::kDifficulty)->put(key, difficulty_bytes);
    txn->open(db::table::kBlockReceipts)->put(key, Bytes(genesis_receipts, 1));
    // Write Chain Config
    auto chain_config{genesis_json["config"].dump()};
    txn->open(db::table::kConfig)->put(full_view(blockhash.bytes), Bytes(reinterpret_cast<const uint8_t *>(chain_config.c_str()), chain_config.size()));
    lmdb::err_handler(txn->commit());
    txn.reset();
    SILKWORM_LOG(LogLevel::Info) << "Database Initiliazed" << std::endl;
}
