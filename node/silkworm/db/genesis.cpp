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

#include "genesis.hpp"

#include <silkworm/state/in_memory_state.hpp>
#include <silkworm/trie/hash_builder.hpp>

#include "tables.hpp"

namespace silkworm::db {
std::pair<bool, std::vector<std::string>> validate_genesis_json(const nlohmann::json& genesis_json) {
    std::pair<bool, std::vector<std::string>> ret{true, {}};
    if (genesis_json.is_discarded()) {
        ret.second.emplace_back("Invalid json data");
    } else {
        if (!genesis_json.contains("difficulty")) {
            ret.second.emplace_back("Missing difficulty member");
        } else {
            auto str{genesis_json["difficulty"].get<std::string>()};
            auto bytes = from_hex(str);
            if (!bytes.has_value()) {
                ret.second.emplace_back("Member difficulty is not a valid hex");
            }
        }
        if (!genesis_json.contains("gasLimit")) ret.second.emplace_back("Missing gasLimit member");
        if (!genesis_json.contains("timestamp")) ret.second.emplace_back("Missing timestamp member");
        if (!genesis_json.contains("extraData")) ret.second.emplace_back("Missing extraData member");
        if (!genesis_json.contains("config")) {
            ret.second.emplace_back("Missing config member");
        } else {
            if (!genesis_json["config"].is_object()) {
                ret.second.emplace_back("Member config is not object");
            } else {
                auto& genesis_config_json{genesis_json["config"]};
                const auto chain_config = ChainConfig::from_json(genesis_config_json);
                if (!chain_config.has_value()) {
                    ret.second.emplace_back("Incomplete / Wrong genesis config member");
                } else {
                    if (chain_config->seal_engine == SealEngineType::kEthash) {
                        if (!genesis_json.contains("mixhash") || !genesis_json["mixhash"].is_string() ||
                            !genesis_json.contains("nonce") || !genesis_json["nonce"].is_string()) {
                            ret.second.emplace_back("Missing mixhash and or nonce member for ethash PoW chain");
                        } else {
                            auto mixhash = from_hex(genesis_json["mixhash"].get<std::string>());
                            if (!mixhash.has_value() || mixhash->length() != kHashLength) {
                                ret.second.emplace_back("mixhash member is not a valid hash hex string");
                            }
                            auto nonce = from_hex(genesis_json["nonce"].get<std::string>());
                            if (!nonce.has_value()) {
                                ret.second.emplace_back("nonce member is not a valid hex string");
                            }
                        }
                    }
                }
            }
        }

        if (genesis_json.contains("alloc")) {
            if (!genesis_json["alloc"].is_object()) {
                ret.second.emplace_back("alloc member is not object");
            } else {
                // Check for sanity of allocations
                // NOTE ! There is no need to check for uniqueness of keys as,
                // being an object, keys are already unique (otherwise parsing of Json fails)
                for (auto& item : genesis_json["alloc"].items()) {
                    if (!item.value().is_object() || !item.value().contains("balance") ||
                        !item.value()["balance"].is_string()) {
                        ret.second.emplace_back("Allocation for  " + item.key() + " is badly formatted");
                        continue;
                    }

                    auto address_bytes{from_hex(item.key())};
                    if (!address_bytes.has_value() || address_bytes->length() != kAddressLength) {
                        ret.second.emplace_back("Allocation for " + item.key() + " has invalid address");
                        continue;
                    }

                    try {
                        auto balance_str{item.value()["balance"].get<std::string>()};
                        (void)intx::from_string<intx::uint256>(balance_str);
                    } catch (const std::exception&) {
                        ret.second.emplace_back("Allocation for " + item.key() + " has bad balance");
                    }
                }
            }
        }
    }

    ret.first = ret.second.empty();
    return ret;
}
bool initialize_genesis(mdbx::txn& txn, const nlohmann::json& genesis_json, bool allow_exceptions) {
    if (!txn.is_readwrite()) {
        if (!allow_exceptions) {
            return false;
        }
        throw std::runtime_error("Unable to write to db with a RO transaction");
    }

    auto existing_config{read_chain_config(txn)};
    if (existing_config.has_value()) {
        if (!allow_exceptions) {
            return false;
        }
        throw std::runtime_error("This database is already initialized with genesis");
    }

    // Validate json payload
    auto [valid, errors]{validate_genesis_json(genesis_json)};
    if (!valid) {
        if (!allow_exceptions) {
            return false;
        }
        const char* delim{"\n"};
        std::ostringstream imploded;
        std::copy(errors.begin(), errors.end(), std::ostream_iterator<std::string>(imploded, delim));
        throw std::runtime_error("Invalid genesis json payload. Examine following errors:\n" + imploded.str());
    }

    try {
        InMemoryState state_buffer{};
        evmc::bytes32 state_root_hash{kEmptyRoot};
        const auto chain_config = ChainConfig::from_json(genesis_json["config"]);

        // Allocate accounts
        if (genesis_json.contains("alloc")) {
            auto expected_allocations{genesis_json["alloc"].size()};

            for (auto& item : genesis_json["alloc"].items()) {
                auto address_bytes{from_hex(item.key())};
                evmc::address account_address = to_evmc_address(*address_bytes);
                auto balance_str{item.value()["balance"].get<std::string>()};
                Account account{0, intx::from_string<intx::uint256>(balance_str)};
                state_buffer.update_account(account_address, std::nullopt, account);
            }

            auto applied_allocations{static_cast<size_t>(state_buffer.account_changes().at(0).size())};
            if (applied_allocations != expected_allocations) {
                // Maybe some account alloc has been inserted twice ?
                throw std::logic_error("Allocations mismatch. Check uniqueness of accounts");
            }

            // Write allocations to db - no changes only accounts
            // Also compute state_root_hash in a single pass
            std::map<evmc::bytes32, Bytes> account_rlp;
            auto state_table{db::open_cursor(txn, db::table::kPlainState)};
            for (const auto& [address, account] : state_buffer.accounts()) {
                // Store account plain state
                Bytes encoded{account.encode_for_storage()};
                state_table.upsert(db::to_slice(address), db::to_slice(encoded));

                // First pass for state_root_hash
                ethash::hash256 hash{keccak256(address)};
                account_rlp[to_bytes32(hash.bytes)] = account.rlp(kEmptyRoot);
            }

            trie::HashBuilder hb;
            for (const auto& [hash, rlp] : account_rlp) {
                hb.add_leaf(trie::unpack_nibbles(hash), rlp);
            }
            state_root_hash = hb.root_hash();
        }

        // Fill Header and Body
        BlockHeader header;
        BlockBody body{};

        auto extra_data = from_hex(genesis_json["extraData"].get<std::string>());
        if (extra_data.has_value()) {
            header.extra_data = extra_data.value();
        }

        if (chain_config->seal_engine == SealEngineType::kEthash && genesis_json.contains("mixhash")) {
            auto mixhash = from_hex(genesis_json["mixhash"].get<std::string>());
            std::memcpy(header.mix_hash.bytes, mixhash->data(), mixhash->size());
        }
        if (genesis_json.contains("nonce")) {
            auto nonce = from_hex(genesis_json["nonce"].get<std::string>());
            if (nonce.has_value() && nonce->length() == sizeof(uint64_t)) {  // 0x0 is not passing right now
                std::memcpy(header.nonce.data(), nonce->data(), nonce->size());
            }
        }
        if (genesis_json.contains("difficulty")) {
            auto difficulty_str{genesis_json["difficulty"].get<std::string>()};
            header.difficulty = intx::from_string<intx::uint256>(difficulty_str);
        }

        header.ommers_hash = kEmptyListHash;
        header.state_root = state_root_hash;
        header.transactions_root = kEmptyRoot;
        header.receipts_root = kEmptyRoot;
        header.gas_limit = std::stoull(genesis_json["gasLimit"].get<std::string>(), nullptr, 0);
        header.timestamp = std::stoull(genesis_json["timestamp"].get<std::string>(), nullptr, 0);

        auto block_hash{header.hash()};
        auto block_hash_key{db::block_key(header.number, block_hash.bytes)};
        db::write_header(txn, header, /*with_header_numbers=*/true);  // Write table::kHeaders and table::kHeaderNumbers
        db::write_canonical_header_hash(txn, block_hash.bytes, header.number);  // Insert header hash as canonical
        db::write_total_difficulty(txn, block_hash_key, header.difficulty);     // Write initial difficulty

        db::write_body(txn, BlockBody(), block_hash.bytes, header.number);  // Write block body (empty)
        db::write_head_header_hash(txn, block_hash.bytes);                  // Update head header in config

        // TODO(Andrea) verify how receipts are stored (see buffer.cpp)
        const uint8_t genesis_null_receipts[] = {0xf6};  // <- cbor encoded
        db::open_cursor(txn, db::table::kBlockReceipts)
            .upsert(db::to_slice(block_hash_key).safe_middle(0, 8), db::to_slice(Bytes(genesis_null_receipts, 1)));

        // Write Chain Settings
        auto config_data{genesis_json["config"].dump()};
        db::open_cursor(txn, db::table::kConfig)
            .upsert(db::to_slice(block_hash.bytes), mdbx::slice{config_data.c_str()});

        return true;

    } catch (const std::exception&) {
        if (!allow_exceptions) {
            return false;
        }
        throw;
    }
}

}  // namespace silkworm::db