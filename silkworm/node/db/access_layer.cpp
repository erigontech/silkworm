/*
   Copyright 2022 The Silkworm Authors

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

#include <stdexcept>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/cast.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/node/db/bitmap.hpp>
#include <silkworm/node/db/tables.hpp>

namespace silkworm::db {

std::optional<VersionBase> read_schema_version(ROTxn& txn) {
    auto cursor = txn.ro_cursor(db::table::kDatabaseInfo);
    if (!cursor->seek(mdbx::slice{kDbSchemaVersionKey})) {
        return std::nullopt;
    }

    auto data{cursor->current()};
    SILKWORM_ASSERT(data.value.length() == 12);
    auto Major{endian::load_big_u32(static_cast<uint8_t*>(data.value.data()))};
    data.value.remove_prefix(sizeof(uint32_t));
    auto Minor{endian::load_big_u32(static_cast<uint8_t*>(data.value.data()))};
    data.value.remove_prefix(sizeof(uint32_t));
    auto Patch{endian::load_big_u32(static_cast<uint8_t*>(data.value.data()))};
    return VersionBase{Major, Minor, Patch};
}

void write_schema_version(RWTxn& txn, const VersionBase& schema_version) {
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

    PooledCursor src(txn, db::table::kDatabaseInfo);
    src.upsert(mdbx::slice{kDbSchemaVersionKey}, to_slice(value));
}

void write_build_info_height(RWTxn& txn, Bytes key, BlockNum height) {
    auto cursor = txn.rw_cursor(db::table::kDatabaseInfo);
    Bytes value{db::block_key(height)};
    cursor->upsert(db::to_slice(key), db::to_slice(value));
}

std::vector<std::string> read_snapshots(ROTxn& txn) {
    auto db_info_cursor = txn.ro_cursor(table::kDatabaseInfo);
    if (!db_info_cursor->seek(mdbx::slice{kDbSnapshotsKey})) {
        return {};
    }
    const auto data{db_info_cursor->current()};
    // https://github.com/nlohmann/json/issues/2204
    const auto json = nlohmann::json::parse(data.value.as_string(), nullptr, /*.allow_exceptions=*/false);
    return json.get<std::vector<std::string>>();
}

void write_snapshots(RWTxn& txn, const std::vector<std::string>& snapshot_file_names) {
    auto db_info_cursor = txn.rw_cursor(table::kDatabaseInfo);
    nlohmann::json json_value = snapshot_file_names;
    db_info_cursor->upsert(mdbx::slice{kDbSnapshotsKey}, mdbx::slice(json_value.dump().data()));
}

std::optional<BlockHeader> read_header(ROTxn& txn, BlockNum block_number, const evmc::bytes32& hash) {
    return read_header(txn, block_number, hash.bytes);
}

std::optional<BlockHeader> read_header(ROTxn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_number, hash)};
    return read_header(txn, key);
}

std::optional<BlockHeader> read_header(ROTxn& txn, ByteView key) {
    auto raw_header{read_header_raw(txn, key)};
    if (raw_header.empty()) {
        return std::nullopt;
    }
    BlockHeader header;
    ByteView encoded_header{raw_header.data(), raw_header.length()};
    success_or_throw(rlp::decode(encoded_header, header));
    return header;
}

Bytes read_header_raw(ROTxn& txn, ByteView key) {
    auto cursor = txn.ro_cursor(db::table::kHeaders);
    auto data{cursor->find(to_slice(key), false)};
    if (!data) {
        return {};
    }
    return Bytes{from_slice(data.value)};
}

std::optional<BlockHeader> read_header(ROTxn& txn, const evmc::bytes32& hash) {
    auto block_num = read_block_number(txn, hash);
    if (!block_num) {
        return std::nullopt;
    }
    return read_header(txn, *block_num, hash.bytes);
}

bool read_header(ROTxn& txn, const evmc::bytes32& hash, BlockNum number, BlockHeader& header) {
    const Bytes key{block_key(number, hash.bytes)};
    const auto raw_header{read_header_raw(txn, key)};
    if (raw_header.empty()) {
        return false;
    }
    ByteView raw_header_view(raw_header);
    success_or_throw(rlp::decode(raw_header_view, header));
    return true;
}

std::vector<BlockHeader> read_headers(ROTxn& txn, BlockNum height) {
    std::vector<BlockHeader> headers;
    process_headers_at_height(txn, height, [&](BlockHeader&& header) {
        headers.emplace_back(std::move(header));
    });
    return headers;
}

// process headers at specific height
size_t process_headers_at_height(ROTxn& txn, BlockNum height, std::function<void(BlockHeader&&)> process_func) {
    auto headers_cursor = txn.ro_cursor(db::table::kHeaders);
    auto key_prefix{db::block_key(height)};

    auto count = db::cursor_for_prefix(
        *headers_cursor, key_prefix,
        [&process_func]([[maybe_unused]] ByteView key, ByteView raw_header) {
            if (raw_header.empty()) throw std::logic_error("empty header in table Headers");
            BlockHeader header;
            ByteView encoded_header{raw_header.data(), raw_header.length()};
            success_or_throw(rlp::decode(encoded_header, header));
            process_func(std::move(header));
        },
        db::CursorMoveDirection::Forward);

    return count;
}

void write_header(RWTxn& txn, const BlockHeader& header, bool with_header_numbers) {
    write_header_ex(txn, header, with_header_numbers);
}

evmc::bytes32 write_header_ex(RWTxn& txn, const BlockHeader& header, bool with_header_numbers) {
    Bytes value{};
    rlp::encode(value, header);
    auto header_hash = bit_cast<evmc_bytes32>(keccak256(value));  // avoid header.hash() because it re-does rlp encoding
    auto key{db::block_key(header.number, header_hash.bytes)};
    auto skey = db::to_slice(key);
    auto svalue = db::to_slice(value);

    auto target = txn.rw_cursor(table::kHeaders);
    target->upsert(skey, svalue);
    if (with_header_numbers) {
        write_header_number(txn, header_hash.bytes, header.number);
    }
    return header_hash;
}

std::optional<ByteView> read_rlp_encoded_header(ROTxn& txn, BlockNum bn, const evmc::bytes32& hash) {
    auto header_cursor = txn.ro_cursor(db::table::kHeaders);
    auto key = db::block_key(bn, hash.bytes);
    auto data = header_cursor->find(db::to_slice(key), /*throw_notfound*/ false);
    if (!data) return std::nullopt;
    return db::from_slice(data.value);
}

std::optional<BlockHeader> read_canonical_header(ROTxn& txn, BlockNum b) {  // also known as read-header-by-number
    std::optional<evmc::bytes32> h = read_canonical_hash(txn, b);
    if (!h) {
        return std::nullopt;  // not found
    }
    return read_header(txn, b, h->bytes);
}

static Bytes header_numbers_key(evmc::bytes32 hash) {
    return {hash.bytes, 32};
}

std::optional<BlockNum> read_block_number(ROTxn& txn, const evmc::bytes32& hash) {
    auto blockhashes_cursor = txn.ro_cursor(db::table::kHeaderNumbers);
    auto key = header_numbers_key(hash);
    auto data = blockhashes_cursor->find(db::to_slice(key), /*throw_notfound*/ false);
    if (!data) {
        return std::nullopt;
    }
    auto block_num = endian::load_big_u64(static_cast<const unsigned char*>(data.value.data()));
    return block_num;
}

void write_header_number(RWTxn& txn, const uint8_t (&hash)[kHashLength], const BlockNum number) {
    auto target = txn.rw_cursor(table::kHeaderNumbers);
    auto value{db::block_key(number)};
    target->upsert({hash, kHashLength}, to_slice(value));
}

std::optional<intx::uint256> read_total_difficulty(ROTxn& txn, BlockNum b, const evmc::bytes32& hash) {
    return db::read_total_difficulty(txn, b, hash.bytes);
}

std::optional<intx::uint256> read_total_difficulty(ROTxn& txn, BlockNum block_number,
                                                   const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_number, hash)};
    return read_total_difficulty(txn, key);
}

std::optional<intx::uint256> read_total_difficulty(ROTxn& txn, ByteView key) {
    auto cursor = txn.ro_cursor(table::kDifficulty);
    auto data{cursor->find(to_slice(key), false)};
    if (!data) {
        return std::nullopt;
    }
    intx::uint256 td{0};
    ByteView data_view{from_slice(data.value)};
    success_or_throw(rlp::decode(data_view, td));
    return td;
}

void write_total_difficulty(RWTxn& txn, const Bytes& key, const intx::uint256& total_difficulty) {
    SILKWORM_ASSERT(key.length() == sizeof(BlockNum) + kHashLength);
    Bytes value{};
    rlp::encode(value, total_difficulty);

    auto target = txn.rw_cursor(table::kDifficulty);
    target->upsert(to_slice(key), to_slice(value));
}

void write_total_difficulty(RWTxn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength],
                            const intx::uint256& total_difficulty) {
    auto key{block_key(block_number, hash)};
    write_total_difficulty(txn, key, total_difficulty);
}

void write_total_difficulty(RWTxn& txn, BlockNum block_number, const evmc::bytes32& hash,
                            const intx::uint256& total_difficulty) {
    auto key{block_key(block_number, hash.bytes)};
    write_total_difficulty(txn, key, total_difficulty);
}

std::tuple<BlockNum, evmc::bytes32> read_canonical_head(ROTxn& txn) {
    auto cursor = txn.ro_cursor(table::kCanonicalHashes);
    auto data = cursor->to_last();
    if (!data) return {};
    evmc::bytes32 hash{};
    std::memcpy(hash.bytes, data.value.data(), kHashLength);
    BlockNum bn = endian::load_big_u64(static_cast<const unsigned char*>(data.key.data()));
    return {bn, hash};
}

std::optional<evmc::bytes32> read_canonical_header_hash(ROTxn& txn, BlockNum number) {
    auto cursor = txn.ro_cursor(table::kCanonicalHashes);
    auto key{db::block_key(number)};
    auto data{cursor->find(to_slice(key), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }
    evmc::bytes32 ret{};
    std::memcpy(ret.bytes, data.value.data(), kHashLength);
    return ret;
}

void write_canonical_header(RWTxn& txn, const BlockHeader& header) {
    write_canonical_header_hash(txn, header.hash().bytes, header.number);
}

void write_canonical_header_hash(RWTxn& txn, const uint8_t (&hash)[kHashLength], BlockNum number) {
    auto cursor = txn.rw_cursor(table::kCanonicalHashes);
    auto key{db::block_key(number)};
    cursor->upsert(to_slice(key), db::to_slice(hash));
}

void read_transactions(ROTxn& txn, uint64_t base_id, uint64_t count, std::vector<Transaction>& out) {
    if (count == 0) {
        out.clear();
        return;
    }
    auto cursor = txn.ro_cursor(table::kBlockTransactions);
    read_transactions(*cursor, base_id, count, out);
}

void write_transactions(RWTxn& txn, const std::vector<Transaction>& transactions, uint64_t base_id) {
    if (transactions.empty()) {
        return;
    }

    auto cursor = txn.rw_cursor(table::kBlockTransactions);
    auto key{db::block_key(base_id)};
    for (const auto& transaction : transactions) {
        Bytes value{};
        rlp::encode(value, transaction);
        mdbx::slice value_slice{value.data(), value.length()};
        cursor->put(to_slice(key), &value_slice, MDBX_APPEND);
        ++base_id;
        endian::store_big_u64(key.data(), base_id);
    }
}

void read_transactions(ROCursor& txn_table, uint64_t base_id, uint64_t count, std::vector<Transaction>& v) {
    v.resize(count);
    if (count == 0) {
        return;
    }

    auto key{db::block_key(base_id)};

    uint64_t i{0};
    for (auto data{txn_table.find(to_slice(key), false)}; data.done && i < count;
         data = txn_table.to_next(/*throw_notfound = */ false), ++i) {
        ByteView data_view{from_slice(data.value)};
        success_or_throw(rlp::decode(data_view, v.at(i)));
    }
    SILKWORM_ASSERT(i == count);
}

bool read_block_by_number(ROTxn& txn, BlockNum number, bool read_senders, Block& block) {
    auto canonical_hashes_cursor = txn.ro_cursor(table::kCanonicalHashes);
    const Bytes key{block_key(number)};
    const auto data{canonical_hashes_cursor->find(to_slice(key), false)};
    if (!data) {
        return false;
    }
    SILKWORM_ASSERT(data.value.length() == kHashLength);
    const auto hash_ptr{static_cast<const uint8_t*>(data.value.data())};
    return read_block(txn, std::span<const uint8_t, kHashLength>{hash_ptr, kHashLength}, number, read_senders, block);
}

bool read_block(ROTxn& txn, const evmc::bytes32& hash, BlockNum number, Block& block) {
    // Read header
    read_header(txn, hash, number, block.header);
    // Read body
    return read_body(txn, hash, number, block);  // read_senders == false
}

bool read_block(ROTxn& txn, std::span<const uint8_t, kHashLength> hash, BlockNum number, bool read_senders,
                Block& block) {
    // Read header
    const Bytes key{block_key(number, hash)};
    const auto raw_header{read_header_raw(txn, key)};
    if (raw_header.empty()) {
        return false;
    }
    ByteView raw_header_view(raw_header);
    success_or_throw(rlp::decode(raw_header_view, block.header));

    return read_body(txn, key, read_senders, block);
}

// process blocks at specific height
size_t process_blocks_at_height(ROTxn& txn, BlockNum height, std::function<void(Block&)> process_func, bool read_senders) {
    auto bodies_cursor = txn.ro_cursor(db::table::kBlockBodies);
    auto key_prefix{db::block_key(height)};

    auto count = db::cursor_for_prefix(
        *bodies_cursor, key_prefix,
        [&process_func, &txn, &read_senders](ByteView key, ByteView raw_body) {
            if (raw_body.empty()) throw std::logic_error("empty header in table Headers");
            // read block...
            Block block;
            // ...ommers
            auto body_for_storage = detail::decode_stored_block_body(raw_body);
            std::swap(block.ommers, body_for_storage.ommers);
            // ...transactions
            read_transactions(txn, body_for_storage.base_txn_id, body_for_storage.txn_count, block.transactions);
            // ...senders
            if (!block.transactions.empty() && read_senders) {
                Bytes kkey{key.data(), key.length()};
                db::parse_senders(txn, kkey, block.transactions);
            }
            // ...header
            auto [block_num, hash] = split_block_key(key);
            bool present = read_header(txn, hash, block_num, block.header);
            if (!present) throw std::logic_error("header not found for body number= " + std::to_string(block_num) + ", hash= " + to_hex(hash));
            // invoke handler
            process_func(block);
        },
        db::CursorMoveDirection::Forward);

    return count;
}

bool read_body(ROTxn& txn, const evmc::bytes32& h, BlockNum bn, BlockBody& body) {
    return db::read_body(txn, bn, h.bytes, /*read_senders=*/false, body);
}

bool read_body(ROTxn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength], bool read_senders,
               BlockBody& out) {
    auto key{block_key(block_number, hash)};
    return read_body(txn, key, read_senders, out);
}

bool read_body(ROTxn& txn, const Bytes& key, bool read_senders, BlockBody& out) {
    auto cursor = txn.ro_cursor(table::kBlockBodies);
    auto data{cursor->find(to_slice(key), false)};
    if (!data) {
        return false;
    }
    ByteView data_view{from_slice(data.value)};
    auto body{detail::decode_stored_block_body(data_view)};

    std::swap(out.ommers, body.ommers);
    read_transactions(txn, body.base_txn_id, body.txn_count, out.transactions);
    if (!out.transactions.empty() && read_senders) {
        parse_senders(txn, key, out.transactions);
    }
    return true;
}

bool read_body(ROTxn& txn, const evmc::bytes32& h, BlockBody& body) {
    auto block_num = read_block_number(txn, h);
    if (!block_num) {
        return false;
    }
    return db::read_body(txn, *block_num, h.bytes, /*read_senders=*/false, body);
}

bool read_canonical_block(ROTxn& txn, BlockNum height, Block& block) {
    std::optional<evmc::bytes32> h = read_canonical_hash(txn, height);
    if (!h) return false;

    bool present = read_header(txn, *h, height, block.header);
    if (!present) return false;

    return read_body(txn, *h, height, block);
}

bool has_body(ROTxn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_number, hash)};
    auto cursor = txn.ro_cursor(table::kBlockBodies);
    return cursor->find(to_slice(key), false);
}

bool has_body(ROTxn& txn, BlockNum block_number, const evmc::bytes32& hash) {
    return db::has_body(txn, block_number, hash.bytes);
}

bool has_sibling(ROTxn&, BlockNum) {
    return false;
    // todo: implement!
}

void write_body(RWTxn& txn, const BlockBody& body, const evmc::bytes32& hash, BlockNum bn) {
    write_body(txn, body, hash.bytes, bn);
}

void write_body(RWTxn& txn, const BlockBody& body, const uint8_t (&hash)[kHashLength], const BlockNum number) {
    detail::BlockBodyForStorage body_for_storage{};
    body_for_storage.ommers = body.ommers;
    body_for_storage.txn_count = body.transactions.size();
    body_for_storage.base_txn_id =
        increment_map_sequence(txn, table::kBlockTransactions.name, body_for_storage.txn_count);
    Bytes value{body_for_storage.encode()};
    auto key{db::block_key(number, hash)};

    auto target = txn.rw_cursor(table::kBlockBodies);
    target->upsert(to_slice(key), to_slice(value));

    write_transactions(txn, body.transactions, body_for_storage.base_txn_id);
}

void write_sibling(RWTxn&, const BlockBody&, const evmc::bytes32&, BlockNum) {
    throw std::runtime_error("write_sibling not implemented");
}

static ByteView read_senders_raw(ROTxn& txn, const Bytes& key) {
    auto cursor = txn.ro_cursor(table::kSenders);
    auto data{cursor->find(to_slice(key), /*throw_notfound = */ false)};
    return data ? from_slice(data.value) : ByteView();
}

std::vector<evmc::address> read_senders(ROTxn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_number, hash)};
    return read_senders(txn, key);
}

std::vector<evmc::address> read_senders(ROTxn& txn, const Bytes& key) {
    std::vector<evmc::address> senders{};
    auto data_view{read_senders_raw(txn, key)};
    if (!data_view.empty()) {
        SILKWORM_ASSERT(data_view.length() % kAddressLength == 0);
        senders.resize(data_view.length() / kAddressLength);
        std::memcpy(senders.data(), data_view.data(), data_view.length());
    }
    return senders;
}

void parse_senders(ROTxn& txn, const Bytes& key, std::vector<Transaction>& out) {
    if (out.empty()) {
        return;
    }
    auto data_view{read_senders_raw(txn, key)};
    if (!data_view.empty()) {
        SILKWORM_ASSERT(data_view.length() % kAddressLength == 0);
        SILKWORM_ASSERT(data_view.length() / kAddressLength == out.size());
        auto addresses = reinterpret_cast<const evmc::address*>(data_view.data());
        size_t idx{0};
        for (auto& transaction : out) {
            transaction.from.emplace(addresses[idx++]);
        }
    } else {
        // Might be empty due to pruning
        for (auto& transaction : out) {
            transaction.recover_sender();
        }
    }
}

std::optional<ByteView> read_code(ROTxn& txn, const evmc::bytes32& code_hash) {
    auto cursor = txn.ro_cursor(table::kCode);
    auto key{to_slice(code_hash)};
    auto data{cursor->find(key, /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }
    return from_slice(data.value);
}

// Erigon FindByHistory for account
static std::optional<ByteView> historical_account(ROTxn& txn, const evmc::address& address, BlockNum block_number) {
    auto cursor = txn.ro_cursor_dup_sort(table::kAccountHistory);
    const Bytes history_key{account_history_key(address, block_number)};
    const auto data{cursor->lower_bound(to_slice(history_key), /*throw_notfound=*/false)};
    if (!data || !data.key.starts_with(to_slice(address))) {
        return std::nullopt;
    }

    const auto bitmap{bitmap::parse(data.value)};
    const auto change_block{bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        return std::nullopt;
    }

    cursor->bind(txn, table::kAccountChangeSet);
    const Bytes change_set_key{block_key(*change_block)};
    return find_value_suffix(*cursor, change_set_key, address);
}

// Erigon FindByHistory for storage
static std::optional<ByteView> historical_storage(ROTxn& txn, const evmc::address& address, uint64_t incarnation,
                                                  const evmc::bytes32& location, BlockNum block_number) {
    auto cursor = txn.ro_cursor_dup_sort(table::kStorageHistory);
    const Bytes history_key{storage_history_key(address, location, block_number)};
    const auto data{cursor->lower_bound(to_slice(history_key), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }

    const ByteView k{from_slice(data.key)};
    SILKWORM_ASSERT(k.length() == kAddressLength + kHashLength + sizeof(BlockNum));

    if (k.substr(0, kAddressLength) != ByteView{address} ||
        k.substr(kAddressLength, kHashLength) != ByteView{location}) {
        return std::nullopt;
    }

    const auto bitmap{bitmap::parse(data.value)};
    const auto change_block{bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        return std::nullopt;
    }

    cursor->bind(txn, table::kStorageChangeSet);
    const Bytes change_set_key{storage_change_key(*change_block, address, incarnation)};
    return find_value_suffix(*cursor, change_set_key, location);
}

std::optional<Account> read_account(ROTxn& txn, const evmc::address& address, std::optional<BlockNum> block_num) {
    std::optional<ByteView> encoded{block_num.has_value() ? historical_account(txn, address, block_num.value())
                                                          : std::nullopt};

    if (!encoded.has_value()) {
        auto state_cursor = txn.ro_cursor_dup_sort(table::kPlainState);
        if (auto data{state_cursor->find({address.bytes, sizeof(evmc::address)}, false)}; data.done) {
            encoded.emplace(from_slice(data.value));
        }
    }
    if (!encoded.has_value() || encoded->empty()) {
        return std::nullopt;
    }

    const auto acc_res{Account::from_encoded_storage(encoded.value())};
    success_or_throw(acc_res);
    Account acc{*acc_res};

    if (acc.incarnation > 0 && acc.code_hash == kEmptyHash) {
        // restore code hash
        auto code_cursor = txn.ro_cursor(table::kPlainCodeHash);
        auto key{storage_prefix(address, acc.incarnation)};
        if (auto data{code_cursor->find(to_slice(key), /*throw_notfound*/ false)};
            data.done && data.value.length() == kHashLength) {
            std::memcpy(acc.code_hash.bytes, data.value.data(), kHashLength);
        }
    }

    return acc;
}

evmc::bytes32 read_storage(ROTxn& txn, const evmc::address& address, uint64_t incarnation,
                           const evmc::bytes32& location, std::optional<BlockNum> block_num) {
    std::optional<ByteView> val{block_num.has_value()
                                    ? historical_storage(txn, address, incarnation, location, block_num.value())
                                    : std::nullopt};
    if (!val.has_value()) {
        auto cursor = txn.ro_cursor_dup_sort(table::kPlainState);
        auto key{storage_prefix(address, incarnation)};
        val = find_value_suffix(*cursor, key, location);
    }

    if (!val.has_value()) {
        return {};
    }

    evmc::bytes32 res{};
    SILKWORM_ASSERT(val->length() <= kHashLength);
    std::memcpy(res.bytes + kHashLength - val->length(), val->data(), val->length());
    return res;
}

static std::optional<uint64_t> historical_previous_incarnation() {
    // TODO (Andrew) implement properly
    return std::nullopt;
}

std::optional<uint64_t> read_previous_incarnation(ROTxn& txn, const evmc::address& address,
                                                  std::optional<BlockNum> block_num) {
    if (block_num.has_value()) {
        return historical_previous_incarnation();
    }

    auto cursor = txn.ro_cursor(table::kIncarnationMap);
    if (auto data{cursor->find(to_slice(address), /*throw_notfound=*/false)}; data.done) {
        SILKWORM_ASSERT(data.value.length() == 8);
        return endian::load_big_u64(static_cast<uint8_t*>(data.value.data()));
    }
    return std::nullopt;
}

AccountChanges read_account_changes(ROTxn& txn, BlockNum block_num) {
    AccountChanges changes;

    auto cursor = txn.ro_cursor_dup_sort(table::kAccountChangeSet);
    auto key{block_key(block_num)};
    auto data{cursor->find(to_slice(key), /*throw_notfound=*/false)};
    while (data) {
        SILKWORM_ASSERT(data.value.length() >= kAddressLength);
        evmc::address address;
        std::memcpy(address.bytes, data.value.data(), kAddressLength);
        data.value.remove_prefix(kAddressLength);
        changes[address] = db::from_slice(data.value);
        data = cursor->to_current_next_multi(/*throw_notfound=*/false);
    }

    return changes;
}

StorageChanges read_storage_changes(ROTxn& txn, BlockNum block_num) {
    StorageChanges changes;

    const Bytes block_prefix{block_key(block_num)};

    auto cursor = txn.ro_cursor_dup_sort(table::kStorageChangeSet);
    auto key_prefix{to_slice(block_prefix)};
    auto data{cursor->lower_bound(key_prefix, false)};
    while (data) {
        if (!data.key.starts_with(key_prefix)) {
            break;
        }

        data.key.remove_prefix(key_prefix.length());
        SILKWORM_ASSERT(data.key.length() == kPlainStoragePrefixLength);

        evmc::address address;
        std::memcpy(address.bytes, data.key.data(), kAddressLength);
        data.key.remove_prefix(kAddressLength);
        uint64_t incarnation{endian::load_big_u64(static_cast<uint8_t*>(data.key.data()))};

        SILKWORM_ASSERT(data.value.length() >= kHashLength);
        evmc::bytes32 location;
        std::memcpy(location.bytes, data.value.data(), kHashLength);
        data.value.remove_prefix(kHashLength);

        changes[address][incarnation][location] = db::from_slice(data.value);
        data = cursor->to_next(/*throw_notfound=*/false);
    }

    return changes;
}

std::optional<ChainConfig> read_chain_config(ROTxn& txn) {
    auto canonical_hashes_cursor = txn.ro_cursor(table::kCanonicalHashes);
    auto data{canonical_hashes_cursor->find(to_slice(block_key(0)), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }
    const auto key{data.value};

    canonical_hashes_cursor->bind(txn, table::kConfig);
    data = canonical_hashes_cursor->find(key, /*throw_notfound=*/false);
    if (!data) {
        return std::nullopt;
    }

    // https://github.com/nlohmann/json/issues/2204
    const auto json = nlohmann::json::parse(data.value.as_string(), nullptr, false);
    return ChainConfig::from_json(json);
}

void update_chain_config(RWTxn& txn, const ChainConfig& config) {
    auto genesis_hash{read_canonical_header_hash(txn, 0)};
    if (!genesis_hash.has_value()) {
        return;
    }
    auto cursor = txn.rw_cursor(db::table::kConfig);
    auto config_data{config.to_json().dump()};
    cursor->upsert(db::to_slice(genesis_hash->bytes), mdbx::slice(config_data.data()));
}

static Bytes head_header_key() {
    std::string table_name = db::table::kHeadHeader.name;
    Bytes key{table_name.begin(), table_name.end()};
    return key;
}

void write_head_header_hash(RWTxn& txn, const evmc::bytes32& hash) {
    write_head_header_hash(txn, hash.bytes);
}

void write_head_header_hash(RWTxn& txn, const uint8_t (&hash)[kHashLength]) {
    auto target = txn.rw_cursor(table::kHeadHeader);
    Bytes key = head_header_key();
    auto skey = db::to_slice(key);

    target->upsert(skey, to_slice(hash));
}

std::optional<evmc::bytes32> read_head_header_hash(ROTxn& txn) {
    auto cursor = txn.ro_cursor(table::kHeadHeader);
    Bytes key = head_header_key();
    auto skey = db::to_slice(key);
    auto data{cursor->find(skey, /*throw_notfound=*/false)};
    if (!data || data.value.length() != kHashLength) {
        return std::nullopt;
    }
    return to_bytes32(from_slice(data.value));
}

std::optional<evmc::bytes32> read_canonical_hash(ROTxn& txn, BlockNum b) {  // throws db exceptions
    auto hashes_table = txn.ro_cursor(db::table::kCanonicalHashes);
    // accessing this table with only b we will get the hash of the canonical block at height b
    auto key = db::block_key(b);
    auto data = hashes_table->find(db::to_slice(key), /*throw_notfound*/ false);
    if (!data) return std::nullopt;  // not found
    assert(data.value.length() == kHashLength);
    return to_bytes32(from_slice(data.value));  // copy
}

void write_canonical_hash(RWTxn& txn, BlockNum b, const evmc::bytes32& hash) {
    Bytes key = db::block_key(b);
    auto skey = db::to_slice(key);
    auto svalue = db::to_slice(hash);

    auto hashes_cursor = txn.rw_cursor(db::table::kCanonicalHashes);
    hashes_cursor->upsert(skey, svalue);
}

void delete_canonical_hash(RWTxn& txn, BlockNum b) {
    auto hashes_cursor = txn.rw_cursor(db::table::kCanonicalHashes);
    Bytes key = db::block_key(b);
    auto skey = db::to_slice(key);
    (void)hashes_cursor->erase(skey);
}

uint64_t increment_map_sequence(RWTxn& txn, const char* map_name, uint64_t increment) {
    uint64_t current_value{read_map_sequence(txn, map_name)};
    if (increment) {
        auto target = txn.rw_cursor(table::kSequence);
        mdbx::slice key(map_name);
        uint64_t new_value{current_value + increment};  // Note ! May overflow
        Bytes new_data(sizeof(uint64_t), '\0');
        endian::store_big_u64(new_data.data(), new_value);
        target->upsert(key, to_slice(new_data));
    }
    return current_value;
}

uint64_t read_map_sequence(ROTxn& txn, const char* map_name) {
    auto target = txn.ro_cursor(table::kSequence);
    mdbx::slice key(map_name);
    auto data{target->find(key, /*throw_notfound=*/false)};
    if (!data.done) {
        return 0;
    }
    if (data.value.length() != sizeof(uint64_t)) {
        throw std::length_error("Bad sequence value in db");
    }
    return endian::load_big_u64(from_slice(data.value).data());
}

uint64_t reset_map_sequence(RWTxn& txn, const char* map_name, uint64_t new_sequence) {
    uint64_t current_sequence{read_map_sequence(txn, map_name)};
    if (new_sequence != current_sequence) {
        auto target = txn.rw_cursor(table::kSequence);
        mdbx::slice key(map_name);
        Bytes new_sequence_buffer(sizeof(uint64_t), '\0');
        endian::store_big_u64(new_sequence_buffer.data(), new_sequence);
        target->upsert(key, to_slice(new_sequence_buffer));
    }
    return current_sequence;
}

const std::string kHeadBlockHash = "headBlockHash";
const std::string kSafeBlockHash = "safeBlockHash";
const std::string kFinalizedBlockHash = "finalizedBlockHash";

std::optional<evmc::bytes32> read_last_fcu_field(ROTxn& txn, const std::string& field) {
    auto cursor = txn.ro_cursor(table::kLastForkchoice);

    Bytes key{field.begin(), field.end()};
    auto skey = db::to_slice(key);

    auto data{cursor->find(skey, /*throw_notfound=*/false)};
    if (!data || data.value.length() != kHashLength) {
        return std::nullopt;
    }
    return to_bytes32(from_slice(data.value));
}

void write_last_fcu_field(RWTxn& txn, const std::string& field, const evmc::bytes32& hash) {
    auto cursor = txn.rw_cursor(table::kLastForkchoice);

    Bytes key{field.begin(), field.end()};
    auto skey = db::to_slice(key);

    cursor->upsert(skey, to_slice(hash));
}

std::optional<evmc::bytes32> read_last_head_block(ROTxn& txn) {
    return read_last_fcu_field(txn, kHeadBlockHash);
}

std::optional<evmc::bytes32> read_last_safe_block(ROTxn& txn) {
    return read_last_fcu_field(txn, kSafeBlockHash);
}

std::optional<evmc::bytes32> read_last_finalized_block(ROTxn& txn) {
    return read_last_fcu_field(txn, kFinalizedBlockHash);
}

void write_last_head_block(RWTxn& txn, const evmc::bytes32& hash) {
    write_last_fcu_field(txn, kHeadBlockHash, hash);
}

void write_last_safe_block(RWTxn& txn, const evmc::bytes32& hash) {
    write_last_fcu_field(txn, kSafeBlockHash, hash);
}

void write_last_finalized_block(RWTxn& txn, const evmc::bytes32& hash) {
    write_last_fcu_field(txn, kFinalizedBlockHash, hash);
}

void DataModel::set_snapshot_repository(snapshot::SnapshotRepository* repository) {
    SILKWORM_ASSERT(repository);
    repository_ = repository;
}

DataModel::DataModel(ROTxn& txn) : txn_{txn} {}

std::optional<BlockHeader> DataModel::read_header(BlockNum block_number, const uint8_t (&block_hash)[kHashLength]) {
    // Assume recent blocks are more probable: first, lookup the block header in the db
    auto block_header{db::read_header(txn_, block_number, block_hash)};
    if (block_header) {
        return block_header;
    }

    // Then, search for it into the snapshots (if any)
    return read_header_from_snapshot(block_number);
}

std::optional<BlockHeader> DataModel::read_header(BlockNum block_number, const evmc::bytes32& block_hash) {
    // Assume recent blocks are more probable: first, lookup the block header in the db
    auto block_header{db::read_header(txn_, block_number, block_hash)};
    if (block_header) {
        return block_header;
    }

    // Then, search for it in the snapshots (if any)
    return read_header_from_snapshot(block_number);
}

std::optional<BlockHeader> DataModel::read_header(const evmc::bytes32& block_hash) {
    // Assume recent blocks are more probable: first, lookup the block header in the db
    auto block_header{db::read_header(txn_, block_hash)};
    if (block_header) {
        return block_header;
    }

    // Then, search for it in the snapshots (if any)
    return read_header_from_snapshot(block_hash);
}

std::optional<BlockNum> DataModel::read_block_number(const evmc::bytes32& hash) {
    return db::read_block_number(txn_, hash);
}

bool DataModel::read_body(const Bytes& key, bool read_senders, BlockBody& out) {
    return db::read_body(txn_, key, read_senders, out);
}

bool DataModel::read_body(BlockNum block_number, const uint8_t (&hash)[kHashLength],
                          bool read_senders, BlockBody& out) {
    return db::read_body(txn_, block_number, hash, read_senders, out);
}

bool DataModel::read_body(const evmc::bytes32& hash, BlockNum bn, BlockBody& body) {
    return db::read_body(txn_, hash, bn, body);
}

bool DataModel::read_body(const evmc::bytes32& hash, BlockBody& body) {
    return db::read_body(txn_, hash, body);
}

bool DataModel::read_canonical_block(BlockNum height, Block& block) {
    return db::read_canonical_block(txn_, height, block);
}

bool DataModel::has_body(BlockNum block_number, const uint8_t (&hash)[kHashLength]) {
    return db::has_body(txn_, block_number, hash);
}

bool DataModel::has_body(BlockNum block_number, const evmc::bytes32& hash) {
    return db::has_body(txn_, block_number, hash);
}

bool DataModel::has_sibling(BlockNum block_number) {
    return db::has_sibling(txn_, block_number);
}

bool DataModel::read_block_by_number(BlockNum number, bool read_senders, Block& block) {
    return db::read_block_by_number(txn_, number, read_senders, block);
}

bool DataModel::read_block(std::span<const uint8_t, kHashLength> hash, BlockNum number,
                           bool read_senders, Block& block) {
    return db::read_block(txn_, hash, number, read_senders, block);
}

bool DataModel::read_block(const evmc::bytes32& hash, BlockNum number, Block& block) {
    return db::read_block(txn_, hash, number, block);
}

std::optional<BlockHeader> DataModel::read_header_from_snapshot(BlockNum block_height) {
    if (!repository_) {
        return {};
    }

    std::optional<BlockHeader> block_header;
    // We know the header snapshot in advance: find it based on target block number
    const auto header_snapshot = repository_->find_header_segment(block_height);
    if (header_snapshot) {
        block_header = header_snapshot->header_by_number(block_height);
    }
    return block_header;
}

std::optional<BlockHeader> DataModel::read_header_from_snapshot(const evmc::bytes32& block_hash) {
    if (!repository_) {
        return {};
    }

    std::optional<BlockHeader> block_header;
    // We don't know the header snapshot in advance: search for block hash in each header snapshot in reverse order
    repository_->view_header_segments([&](const snapshot::HeaderSnapshot* snapshot) -> bool {
        block_header = snapshot->header_by_hash(block_hash);
        return block_header.has_value();
    });
    return block_header;
}

}  // namespace silkworm::db
