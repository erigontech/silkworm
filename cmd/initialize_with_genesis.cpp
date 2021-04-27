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

#include <stdlib.h>

#include <filesystem>
#include <fstream>
#include <iostream>

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/chain_genesis.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/trie/hash_builder.hpp>
#include <silkworm/types/account.hpp>

using namespace silkworm;

constexpr uint8_t genesis_body[] = {195, 128, 128, 192};
constexpr uint8_t genesis_receipts[] = {246};

std::string last_header_key = "LastHeader";

int main(int argc, char* argv[]) {
    namespace fs = std::filesystem;
    int chain_id{-1};
    CLI::App app{"Initializes database with genesis json file"};

    std::string out;
    std::string genesis;
    size_t map_size{
        1 *
        kMebi};  // As we're basically creating a new db set an initial map_size (Windows does not create it without)

    app.add_option("--out", out, "Path to new chaindata folder (must exist)", true)
        ->required()
        ->check(CLI::ExistingDirectory);

    auto genesis_opt =
        app.add_option("--genesis", genesis, "Path to the genesis json file", true)->check(CLI::ExistingFile);
    auto chain_id_opt = app.add_option("--chainid", chain_id, "Specify id of the chain to generate")
                            ->excludes(genesis_opt)
                            ->check(CLI::Range(0u, 65535u));

    CLI11_PARSE(app, argc, argv);

    // Either --chainId or --genesis are mandatory
    if (!genesis_opt->count() && !chain_id_opt->count()) {
        std::cerr << "\nError: Provide either a custom --genesis file or a known --chainid" << std::endl;
        return -1;
    }

    // Check destination directory
    if (fs::exists(fs::path(out) / fs::path("data.mdb"))) {
        std::cerr << "\nError : A data file (data.mdb) already exists in target folder" << std::endl;
        return -1;
    }

    // Read data from selected source
    std::string source_data;

    // If provided a json file parse it
    if (genesis_opt->count()) {
        std::ifstream t(genesis.data());
        source_data = std::string((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
    } else {
        // Parse from a known set of configs
        switch (chain_id) {
            case 1:
                assert(sizeof_genesis_mainnet_data() != 0);
                source_data.assign(genesis_mainnet_data(), sizeof_genesis_mainnet_data());
                break;
            case 4:
                assert(sizeof_genesis_rinkeby_data() != 0);
                source_data.assign(genesis_rinkeby_data(), sizeof_genesis_rinkeby_data());
                break;
            case 5:
                assert(sizeof_genesis_goerli_data() != 0);
                source_data.assign(genesis_goerli_data(), sizeof_genesis_goerli_data());
                break;
            default:
                // TODO Configs for ETC and Ropsten
                SILKWORM_LOG(LogLevel::Error) << "Unknown chain id: " << chain_id << std::endl;
                return -1;
        }
    }

    // Parse Json data
    // N.B. = instead of {} initialization due to https://github.com/nlohmann/json/issues/2204
    auto genesis_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);
    if (genesis_json == nlohmann::json::value_t::discarded) {
        std::cerr << "\nError : Provided data is not a valid JSON format" << std::endl;
        return -1;
    }

    // Sanity checks over collected data
    std::string err{};
    if (!genesis_json.contains("difficulty")) err.append("* Missing difficulty member\n");
    if (!genesis_json.contains("nonce")) err.append("* Missing nonce member\n;");
    if (!genesis_json.contains("gasLimit")) err.append("* Missing gasLimit member\n;");
    if (!genesis_json.contains("timestamp")) err.append("* Missing timestamp member\n;");
    if (!genesis_json.contains("extraData")) err.append("* Missing extraData member\n;");
    if (!genesis_json.contains("config")) {
        err.append("* Missing config member\n;");
    } else {
        if (!genesis_json["config"].is_object()) {
            err.append("* Member config is not object");
        } else {
            if (genesis_json["config"].contains("ethash") &&
                (!genesis_json.contains("mixhash") || !genesis_json["mixhash"].is_string())) {
                err.append("Missing mixhash member for ethash PoW chain");
            }
        }
    }
    if (genesis_json.contains("alloc") && !genesis_json["alloc"].is_object()) {
        err.append("* alloc member is not object");
    }

    if (!err.empty()) {
        std::cerr << "\nError : Incomplete genesis Json data : \n" << err << std::endl;
        return -1;
    }

    // Try parse genesis config
    {
        auto genesis_json_config = genesis_json["config"];
        auto chain_config = db::parse_chain_config(genesis_json_config.dump());
        if (!chain_config.has_value()) {
            std::cerr << "\nError : Incomplete / wrong genesis config member" << std::endl;
            return -1;
        }
    }

    bool res{false};
    try {
        // Prime directories and DB
        lmdb::DatabaseConfig db_config{out};
        db_config.set_readonly(false);
        db_config.map_size = map_size;
        std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
        std::unique_ptr<lmdb::Transaction> txn{env->begin_rw_transaction()};
        db::table::create_all(*txn);

        // Initialize state_buffer for allocations (if any)
        // and get root_hash
        db::Buffer state_buffer(txn.get());

        // Allocate accounts
        if (genesis_json.contains("alloc")) {
            auto expected_allocations{genesis_json["alloc"].size()};

            for (auto& item : genesis_json["alloc"].items()) {
                if (!item.value().is_object() || !item.value().contains("balance") ||
                    !item.value()["balance"].is_string()) {
                    throw std::invalid_argument("alloc address " + item.key() + " has badly formatted allocation");
                }

                auto address_bytes{from_hex(item.key())};
                if (address_bytes == std::nullopt || address_bytes.value().length() != kAddressLength) {
                    throw std::invalid_argument("alloc address " + item.key() +
                                                " is not valid. Either not hex or not " +
                                                std::to_string(kAddressLength) + " bytes");
                }

                evmc::address account_address = to_address(*address_bytes);
                auto balance_str{item.value()["balance"].get<std::string>()};
                Account account{0, intx::from_string<intx::uint256>(balance_str)};
                state_buffer.update_account(account_address, std::nullopt, account);
            }

            auto applied_allocations{static_cast<size_t>(state_buffer.account_changes().at(0).size())};
            if (applied_allocations != expected_allocations) {
                // Maybe some account alloc has been inserted twice ?
                std::cout << "Allocations expected " << expected_allocations << " applied " << applied_allocations
                          << std::endl;
                throw std::logic_error("Allocations mismatch. Check uniqueness of accounts");
            }

            state_buffer.write_to_db();
        }

        // Fill Header
        BlockHeader header;

        auto extra_data = from_hex(genesis_json["extraData"].get<std::string>());
        if (extra_data.has_value()) {
            header.extra_data = *extra_data;
        }

        if (genesis_json.contains("mixhash")) {
            auto mixhash = from_hex(genesis_json["mixhash"].get<std::string>());
            if (!mixhash.has_value() || mixhash->size() != kHashLength) {
                throw std::invalid_argument("mixhash is not an hex hash");
            }
            std::memcpy(header.mix_hash.bytes, mixhash->data(), mixhash->size());
        }

        header.ommers_hash = kEmptyListHash;
        header.state_root = state_buffer.state_root_hash();
        header.transactions_root = kEmptyRoot;
        header.receipts_root = kEmptyRoot;

        auto difficulty_str{genesis_json["difficulty"].get<std::string>()};
        header.difficulty = intx::from_string<intx::uint256>(difficulty_str);
        header.gas_limit = std::stoull(genesis_json["gasLimit"].get<std::string>().c_str(), nullptr, 0);
        header.timestamp = std::stoull(genesis_json["timestamp"].get<std::string>().c_str(), nullptr, 0);

        auto nonce = std::stoull(genesis_json["nonce"].get<std::string>().c_str(), nullptr, 0);
        std::memcpy(&header.nonce[0], &nonce, 8);

        // Write header
        auto block_hash{header.hash()};
        auto block_key{db::block_key(0)};

        Bytes rlp_header;
        rlp::encode(rlp_header, header);

        Bytes key(8 + kHashLength, '\0');
        std::memcpy(&key[8], block_hash.bytes, kHashLength);
        txn->open(db::table::kHeaders)->put(key, rlp_header);
        txn->open(db::table::kCanonicalHashes)->put(block_key, full_view(block_hash.bytes));

        // Write body
        txn->open(db::table::kBlockBodies)->put(key, Bytes(genesis_body, 4));
        txn->open(db::table::kDifficulty)->put(key, intx::as_bytes(header.difficulty));
        txn->open(db::table::kBlockReceipts)->put(key.substr(0, 8), Bytes(genesis_receipts, 1));
        txn->open(db::table::kHeadHeader)
            ->put(Bytes(reinterpret_cast<const uint8_t*>(last_header_key.c_str()), last_header_key.size()),
                  full_view(block_hash.bytes));
        txn->open(db::table::kHeaderNumbers)->put(full_view(block_hash.bytes), key.substr(0, 8));

        // Write Chain Config
        auto config_data{genesis_json["config"].dump()};
        txn->open(db::table::kConfig)->put(full_view(block_hash.bytes), byte_view_of_c_str(config_data.c_str()));

        lmdb::err_handler(txn->commit());
        txn.reset();
        res = true;
    } catch (const std::exception& ex) {
        std::cerr << "\nUnexpected error : " << ex.what() << std::endl;
    }

    if (!res) {
        // Delete created db (if any)
        fs::path out_path(out);
        fs::path out_file_path(out / fs::path("data.mdb"));
        fs::path out_lock_path(out / fs::path("lock.mdb"));
        if (fs::exists(out_file_path)) {
            fs::remove(out_file_path);
        }
        if (fs::exists(out_lock_path)) {
            fs::remove(out_lock_path);
        }
    } else {
        std::cout << "\nDatabase initialized" << std::endl;
    }

    return res ? 0 : -1;
}
