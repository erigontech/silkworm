/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "access_layer.hpp"

#include <cassert>

#include <silkworm/common/endian.hpp>

#include "bitmap.hpp"
#include "tables.hpp"

namespace silkworm::db {

std::optional<VersionBase> read_schema_version(mdbx::txn& txn) noexcept {
    auto src{db::open_cursor(txn, table::kDatabaseInfo)};
    if (!src.seek(mdbx::slice{kDbSchemaVersionKey})) {
        return std::nullopt;
    }

    auto data{src.current()};
    assert(data.value.length() == 12);
    auto Major{endian::load_big_u32(static_cast<uint8_t*>(data.value.iov_base))};
    data.value.remove_prefix(sizeof(uint32_t));
    auto Minor{endian::load_big_u32(static_cast<uint8_t*>(data.value.iov_base))};
    data.value.remove_prefix(sizeof(uint32_t));
    auto Patch{endian::load_big_u32(static_cast<uint8_t*>(data.value.iov_base))};
    return VersionBase{Major, Minor, Patch};
}

void write_schema_version(mdbx::txn& txn, VersionBase& schema_version) {
    auto old_schema_version{read_schema_version(txn)};
    if (old_schema_version.has_value()) {
        if (schema_version == old_schema_version.value()) {
            // Simply return. No changes
            return;
        }
        if (schema_version < old_schema_version.value()) {
            throw std::runtime_error("Cannot downgrade schema version");
        }
    }
    Bytes value(12, '\0');
    endian::store_big_u32(&value[0], schema_version.Major);
    endian::store_big_u32(&value[4], schema_version.Minor);
    endian::store_big_u32(&value[8], schema_version.Patch);
    auto src{db::open_cursor(txn, table::kDatabaseInfo)};
    src.upsert(mdbx::slice{kDbSchemaVersionKey}, to_slice(value));
}

std::optional<BlockHeader> read_header(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]) {
    auto src{db::open_cursor(txn, table::kHeaders)};
    auto key{block_key(block_number, hash)};
    auto data{src.find(to_slice(key), false)};
    if (!data) {
        return std::nullopt;
    }

    BlockHeader header;
    ByteView data_view{from_slice(data.value)};
    rlp::success_or_throw(rlp::decode(data_view, header));
    return header;
}

void write_header(mdbx::txn& txn, const BlockHeader& header, bool with_header_numbers) {
    Bytes value{};
    rlp::encode(value, header);
    auto header_hash{header.hash()};
    auto key{db::block_key(header.number, header_hash.bytes)};
    auto target{db::open_cursor(txn, table::kHeaders)};
    target.upsert(to_slice(key), to_slice(value));
    if (with_header_numbers) {
        write_header_number(txn, header_hash.bytes, header.number);
    }
}

void write_header_number(mdbx::txn& txn, const uint8_t (&hash)[kHashLength], const BlockNum number) {
    auto target{db::open_cursor(txn, db::table::kHeaderNumbers)};
    auto value{db::block_key(number)};
    target.upsert({hash, kHashLength}, to_slice(value));
}

std::optional<intx::uint256> read_total_difficulty(mdbx::txn& txn, BlockNum block_number,
                                                   const uint8_t (&hash)[kHashLength]) {
    auto src{db::open_cursor(txn, table::kDifficulty)};
    auto key{block_key(block_number, hash)};
    auto data{src.find(to_slice(key), false)};
    if (!data) {
        return std::nullopt;
    }
    intx::uint256 td{0};
    ByteView data_view{from_slice(data.value)};
    rlp::success_or_throw(rlp::decode(data_view, td));
    return td;
}

void write_total_difficulty(mdbx::txn& txn, const Bytes& key, const intx::uint256& total_difficulty) {
    assert(key.length() == sizeof(BlockNum) + kHashLength);
    Bytes value{};
    rlp::encode(value, total_difficulty);
    auto target{db::open_cursor(txn, table::kDifficulty)};
    target.upsert(to_slice(key), to_slice(value));
}

void write_total_difficulty(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength],
                            intx::uint256& total_difficulty) {
    auto key{block_key(block_number, hash)};
    write_total_difficulty(txn, key, total_difficulty);
}

void write_canonical_header(mdbx::txn& txn, const BlockHeader& header) {
    write_canonical_header_hash(txn, header.hash().bytes, header.number);
}

void write_canonical_header_hash(mdbx::txn& txn, const uint8_t (&hash)[kHashLength], BlockNum number) {
    auto target{db::open_cursor(txn, table::kCanonicalHashes)};
    auto key{db::block_key(number)};
    mdbx::slice value{hash, kHashLength};
    target.upsert(to_slice(key), value);
}

std::vector<Transaction> read_transactions(mdbx::txn& txn, uint64_t base_id, uint64_t count) {
    if (!count) {
        return {};
    }
    auto src{db::open_cursor(txn, table::kEthTx)};
    return read_transactions(src, base_id, count);
}

void write_transactions(mdbx::txn& txn, const std::vector<Transaction>& transactions, uint64_t base_id) {
    if (transactions.empty()) {
        return;
    }
    auto target{db::open_cursor(txn, table::kEthTx)};
    auto key{db::block_key(base_id)};
    for (const auto& transaction : transactions) {
        Bytes value{};
        rlp::encode(value, transaction);
        mdbx::slice value_slice{value.data(), value.length()};
        target.put(to_slice(key), &value_slice, MDBX_APPEND);
        ++base_id;
        endian::store_big_u64(key.data(), base_id);
    }
}

std::vector<Transaction> read_transactions(mdbx::cursor& txn_table, uint64_t base_id, uint64_t count) {
    std::vector<Transaction> v{};
    if (count == 0) {
        return v;
    }
    v.reserve(count);

    Bytes key(8, '\0');
    endian::store_big_u64(key.data(), base_id);

    uint64_t i{0};
    for (auto data{txn_table.find(to_slice(key), false)}; data.done && i < count;
         data = txn_table.to_next(/*throw_notfound = */ false), ++i) {
        ByteView data_view{from_slice(data.value)};
        Transaction eth_txn;
        rlp::success_or_throw(rlp::decode(data_view, eth_txn));
        v.push_back(eth_txn);
    }

    return v;
}

std::optional<BlockWithHash> read_block(mdbx::txn& txn, BlockNum block_number, bool read_senders) {
    // Locate canonical hash
    auto src{db::open_cursor(txn, table::kCanonicalHashes)};
    auto key{block_key(block_number)};
    auto data{src.find(to_slice(key), false)};
    if (!data) {
        return std::nullopt;
    }

    BlockWithHash bh{};
    assert(data.value.length() == kHashLength);
    std::memcpy(bh.hash.bytes, data.value.iov_base, kHashLength);

    // Locate header
    src = db::open_cursor(txn, table::kHeaders);
    key = block_key(block_number, bh.hash.bytes);
    data = src.find(to_slice(key), false);
    if (!data) {
        return std::nullopt;
    }

    ByteView data_view(from_slice(data.value));
    rlp::success_or_throw(rlp::decode(data_view, bh.block.header));

    // Read body
    std::optional<BlockBody> body{read_body(txn, block_number, bh.hash.bytes, read_senders)};
    if (!body) {
        return std::nullopt;
    }

    std::swap(bh.block.ommers, body->ommers);
    std::swap(bh.block.transactions, body->transactions);

    return bh;
}

std::optional<BlockBody> read_body(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength],
                                   bool read_senders) {
    auto src{db::open_cursor(txn, table::kBlockBodies)};
    auto key{block_key(block_number, hash)};
    auto data{src.find(to_slice(key), false)};
    if (!data) {
        return std::nullopt;
    }
    ByteView data_view{from_slice(data.value)};
    auto body{detail::decode_stored_block_body(data_view)};

    BlockBody out;
    std::swap(out.ommers, body.ommers);
    out.transactions = read_transactions(txn, body.base_txn_id, body.txn_count);

    if (!out.transactions.empty() && read_senders) {
        std::vector<evmc::address> senders{db::read_senders(txn, block_number, hash)};
        // Might be empty due to pruning
        if (!senders.empty()) {
            if (senders.size() != out.transactions.size()) {
                throw MissingSenders("senders count does not match transactions count");
            }
            for (size_t i{0}; i < senders.size(); ++i) {
                out.transactions[i].from = senders[i];
            }
        } else {
            for (auto& transaction : out.transactions) {
                transaction.recover_sender();
            }
        }
    }

    return out;
}

void write_body(mdbx::txn& txn, const BlockBody& body, const uint8_t (&hash)[kHashLength], const BlockNum number) {
    detail::BlockBodyForStorage body_for_storage{};
    body_for_storage.ommers = body.ommers;
    body_for_storage.txn_count = body.transactions.size();
    body_for_storage.base_txn_id = increment_map_sequence(txn, table::kEthTx.name, body_for_storage.txn_count);
    Bytes value{body_for_storage.encode()};
    auto key{db::block_key(number, hash)};
    auto target{db::open_cursor(txn, table::kBlockBodies)};
    target.upsert(to_slice(key), to_slice(value));

    write_transactions(txn, body.transactions, body_for_storage.base_txn_id);
}

std::vector<evmc::address> read_senders(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]) {
    std::vector<evmc::address> senders{};

    auto src{db::open_cursor(txn, table::kSenders)};
    auto key{block_key(block_number, hash)};
    auto data{src.find(to_slice(key), /*throw_notfound = */ false)};
    if (data) {
        assert(data.value.length() % kAddressLength == 0);
        senders.resize(data.value.length() / kAddressLength);
        std::memcpy(senders.data(), data.value.iov_base, data.value.length());
    }
    return senders;
}

std::optional<ByteView> read_code(mdbx::txn& txn, const evmc::bytes32& code_hash) {
    auto src{db::open_cursor(txn, table::kCode)};
    auto key{to_slice(full_view(code_hash))};
    auto data{src.find(key, /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }
    return from_slice(data.value);
}

// Erigon FindByHistory for account
static std::optional<ByteView> historical_account(mdbx::txn& txn, const evmc::address& address, BlockNum block_number) {
    auto history_table{db::open_cursor(txn, table::kAccountHistory)};
    const Bytes history_key{account_history_key(address, block_number)};
    const auto data{history_table.lower_bound(to_slice(history_key), /*throw_notfound=*/false)};
    if (!data || !data.key.starts_with(to_slice(address))) {
        return std::nullopt;
    }

    const auto bitmap{bitmap::read(from_slice(data.value))};
    const auto change_block{bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        return std::nullopt;
    }

    auto change_set_table{db::open_cursor(txn, table::kAccountChangeSet)};
    const Bytes change_set_key{block_key(*change_block)};
    return find_value_suffix(change_set_table, change_set_key, full_view(address));
}

// Erigon FindByHistory for storage
static std::optional<ByteView> historical_storage(mdbx::txn& txn, const evmc::address& address, uint64_t incarnation,
                                                  const evmc::bytes32& location, BlockNum block_number) {
    auto history_table{db::open_cursor(txn, table::kStorageHistory)};
    const Bytes history_key{storage_history_key(address, location, block_number)};
    const auto data{history_table.lower_bound(to_slice(history_key), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }

    const ByteView k{from_slice(data.key)};
    if (k.substr(0, kAddressLength) != full_view(address) ||
        k.substr(kAddressLength, kHashLength) != full_view(location)) {
        return std::nullopt;
    }

    const auto bitmap{bitmap::read(from_slice(data.value))};
    const auto change_block{bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        return std::nullopt;
    }

    auto change_set_table{db::open_cursor(txn, table::kStorageChangeSet)};
    const Bytes change_set_key{storage_change_key(*change_block, address, incarnation)};
    return find_value_suffix(change_set_table, change_set_key, full_view(location));
}

std::optional<Account> read_account(mdbx::txn& txn, const evmc::address& address, std::optional<BlockNum> block_num) {
    std::optional<ByteView> encoded{block_num.has_value() ? historical_account(txn, address, block_num.value())
                                                          : std::nullopt};

    if (!encoded.has_value()) {
        auto src{db::open_cursor(txn, table::kPlainState)};
        if (auto data{src.find({address.bytes, sizeof(evmc::address)}, false)}; data.done) {
            encoded.emplace(from_slice(data.value));
        }
    }
    if (!encoded.has_value() || encoded->empty()) {
        return std::nullopt;
    }

    auto [acc, err]{decode_account_from_storage(encoded.value())};
    rlp::success_or_throw(err);

    if (acc.incarnation > 0 && acc.code_hash == kEmptyHash) {
        // restore code hash
        auto src{db::open_cursor(txn, table::kPlainContractCode)};
        auto key{storage_prefix(full_view(address), acc.incarnation)};
        if (auto data{src.find(to_slice(key), /*throw_notfound*/ false)};
            data.done && data.value.length() == kHashLength) {
            std::memcpy(acc.code_hash.bytes, data.value.iov_base, kHashLength);
        }
    }

    return acc;
}

evmc::bytes32 read_storage(mdbx::txn& txn, const evmc::address& address, uint64_t incarnation,
                           const evmc::bytes32& location, std::optional<BlockNum> block_num) {
    std::optional<ByteView> val{block_num.has_value()
                                    ? historical_storage(txn, address, incarnation, location, block_num.value())
                                    : std::nullopt};
    if (!val.has_value()) {
        auto src{db::open_cursor(txn, table::kPlainState)};
        auto key{storage_prefix(full_view(address), incarnation)};
        val = find_value_suffix(src, key, full_view(location));
    }

    if (!val.has_value()) {
        return {};
    }

    evmc::bytes32 res{};
    assert(val->length() <= kHashLength);
    std::memcpy(res.bytes + kHashLength - val->length(), val->data(), val->length());
    return res;
}

static std::optional<uint64_t> historical_previous_incarnation() {
    // TODO (Andrew) implement properly
    return std::nullopt;
}

std::optional<uint64_t> read_previous_incarnation(mdbx::txn& txn, const evmc::address& address,
                                                  std::optional<BlockNum> block_num) {
    if (block_num.has_value()) {
        return historical_previous_incarnation();
    }

    auto src{db::open_cursor(txn, table::kIncarnationMap)};
    if (auto data{src.find(mdbx::slice{address.bytes, sizeof(evmc::address)}, /*throw_notfound*/ false)}; data.done) {
        assert(data.value.length() == 8);
        return endian::load_big_u64(static_cast<uint8_t*>(data.value.iov_base));
    }
    return std::nullopt;
}

AccountChanges read_account_changes(mdbx::txn& txn, BlockNum block_num) {
    AccountChanges changes;

    auto src{db::open_cursor(txn, table::kAccountChangeSet)};
    auto key{block_key(block_num)};

    auto data{src.find(to_slice(key), /*throw_notfound*/ false)};
    while (data) {
        assert(data.value.length() >= kAddressLength);
        evmc::address address;
        std::memcpy(address.bytes, data.value.iov_base, kAddressLength);
        data.value.remove_prefix(kAddressLength);
        changes[address] = Bytes{static_cast<uint8_t*>(data.value.iov_base), data.value.iov_len};
        data = src.to_current_next_multi(/*throw_not_found*/ false);
    }

    return changes;
}

StorageChanges read_storage_changes(mdbx::txn& txn, BlockNum block_num) {
    StorageChanges changes;

    const Bytes block_prefix{block_key(block_num)};

    auto src{db::open_cursor(txn, table::kStorageChangeSet)};

    auto key_prefix{to_slice(block_prefix)};
    auto data{src.lower_bound(key_prefix, false)};
    while (data) {
        if (!data.key.starts_with(key_prefix)) {
            break;
        }

        data.key.remove_prefix(key_prefix.length());
        assert(data.key.length() == kPlainStoragePrefixLength);

        evmc::address address;
        std::memcpy(address.bytes, data.key.iov_base, kAddressLength);
        data.key.remove_prefix(kAddressLength);
        uint64_t incarnation{endian::load_big_u64(static_cast<uint8_t*>(data.key.iov_base))};

        assert(data.value.length() >= kHashLength);
        evmc::bytes32 location;
        std::memcpy(location.bytes, data.value.iov_base, kHashLength);
        data.value.remove_prefix(kHashLength);

        changes[address][incarnation][location] = Bytes{static_cast<uint8_t*>(data.value.iov_base), data.value.iov_len};
        data = src.to_next(/*throw_notfound=*/false);
    }

    return changes;
}

std::optional<ChainConfig> read_chain_config(mdbx::txn& txn) {
    auto src{db::open_cursor(txn, table::kCanonicalHashes)};
    auto data{src.find(to_slice(block_key(0)), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }

    src = db::open_cursor(txn, table::kConfig);
    const auto key{data.value};
    data = src.find(key, /*throw_notfound=*/false);
    if (!data) {
        return std::nullopt;
    }

    // https://github.com/nlohmann/json/issues/2204
    const auto json = nlohmann::json::parse(data.value.as_string(), nullptr, false);
    return ChainConfig::from_json(json);
}

void write_head_header_hash(mdbx::txn& txn, const uint8_t (&hash)[kHashLength]) {
    auto target{db::open_cursor(txn, table::kConfig)};
    mdbx::slice key(db::table::kLastHeaderKey);
    mdbx::slice value(hash, kHashLength);
    target.upsert(key, value);
}

uint64_t increment_map_sequence(mdbx::txn& txn, const char* map_name, uint64_t increment) {
    uint64_t current_value{read_map_sequence(txn, map_name)};
    if (increment) {
        auto target{db::open_cursor(txn, table::kSequence)};
        mdbx::slice key(map_name);
        uint64_t new_value{current_value + increment};  // Note ! May overflow
        Bytes new_data(sizeof(uint64_t), '\0');
        endian::store_big_u64(new_data.data(), new_value);
        target.upsert(key, to_slice(new_data));
    }
    return current_value;
}

uint64_t read_map_sequence(mdbx::txn& txn, const char* map_name) {
    auto target{db::open_cursor(txn, table::kSequence)};
    mdbx::slice key(map_name);
    auto data{target.find(key, /*throw_notfound=*/false)};
    if (!data.done) {
        return 0;
    }
    if (data.value.length() != sizeof(uint64_t)) {
        throw std::length_error("Bad sequence value in db");
    }
    return endian::load_big_u64(from_slice(data.value).data());
}

}  // namespace silkworm::db
