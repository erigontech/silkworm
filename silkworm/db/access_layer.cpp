// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "access_layer.hpp"

#include <bit>
#include <stdexcept>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/blocks/bodies/body_queries.hpp>
#include <silkworm/db/blocks/headers/header_queries.hpp>
#include <silkworm/db/blocks/transactions/txn_queries.hpp>
#include <silkworm/db/datastore/kvdb/bitmap.hpp>
#include <silkworm/db/receipt_cbor.hpp>
#include <silkworm/db/state/account_codec.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::db {

using namespace silkworm::datastore::kvdb;
using namespace snapshots;
using datastore::kvdb::to_slice;

std::optional<VersionBase> read_schema_version(ROTxn& txn) {
    auto cursor = txn.ro_cursor(table::kDatabaseInfo);
    if (!cursor->seek(mdbx::slice{kDbSchemaVersionKey})) {
        return std::nullopt;
    }

    auto data = cursor->current();
    SILKWORM_ASSERT(data.value.length() == 12);
    const auto major = endian::load_big_u32(static_cast<uint8_t*>(data.value.data()));
    data.value.remove_prefix(sizeof(uint32_t));
    const auto minor = endian::load_big_u32(static_cast<uint8_t*>(data.value.data()));
    data.value.remove_prefix(sizeof(uint32_t));
    const auto patch = endian::load_big_u32(static_cast<uint8_t*>(data.value.data()));
    return VersionBase{major, minor, patch};
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
    endian::store_big_u32(&value[0], schema_version.major);
    endian::store_big_u32(&value[4], schema_version.minor);
    endian::store_big_u32(&value[8], schema_version.patch);

    PooledCursor src(txn, table::kDatabaseInfo);
    src.upsert(mdbx::slice{kDbSchemaVersionKey}, to_slice(value));
}

void write_build_info_block_num(RWTxn& txn, const Bytes& key, BlockNum block_num) {
    auto cursor = txn.rw_cursor(table::kDatabaseInfo);
    Bytes value{block_key(block_num)};
    cursor->upsert(to_slice(key), to_slice(value));
}

std::optional<BlockHeader> read_header(ROTxn& txn, BlockNum block_num, const evmc::bytes32& hash) {
    return read_header(txn, block_num, hash.bytes);
}

std::optional<BlockHeader> read_header(ROTxn& txn, BlockNum block_num, const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_num, hash)};
    return read_header(txn, key);
}

std::optional<BlockHeader> read_header(ROTxn& txn, ByteView key) {
    auto raw_header{read_header_raw(txn, key)};
    if (raw_header.empty()) {
        return std::nullopt;
    }
    BlockHeader header;
    ByteView encoded_header{raw_header.data(), raw_header.size()};
    success_or_throw(rlp::decode(encoded_header, header));
    return header;
}

Bytes read_header_raw(ROTxn& txn, ByteView key) {
    auto cursor = txn.ro_cursor(table::kHeaders);
    auto data{cursor->find(to_slice(key), false)};
    if (!data) {
        return {};
    }
    return Bytes{from_slice(data.value)};
}

std::optional<BlockHeader> read_header(ROTxn& txn, const evmc::bytes32& hash) {
    auto block_num = read_block_num(txn, hash);
    if (!block_num) {
        return std::nullopt;
    }
    return read_header(txn, *block_num, hash.bytes);
}

bool read_header(ROTxn& txn, const evmc::bytes32& hash, BlockNum block_num, BlockHeader& header) {
    const Bytes key{block_key(block_num, hash.bytes)};
    const auto raw_header{read_header_raw(txn, key)};
    if (raw_header.empty()) {
        return false;
    }
    ByteView raw_header_view(raw_header);
    success_or_throw(rlp::decode(raw_header_view, header));
    return true;
}

std::vector<BlockHeader> read_headers(ROTxn& txn, BlockNum block_num) {
    std::vector<BlockHeader> headers;
    read_headers(txn, block_num, [&](BlockHeader header) {
        headers.emplace_back(std::move(header));
    });
    return headers;
}

size_t read_headers(ROTxn& txn, BlockNum block_num, std::function<void(BlockHeader)> process_func) {
    auto headers_cursor = txn.ro_cursor(table::kHeaders);
    auto key_prefix{block_key(block_num)};

    auto count = cursor_for_prefix(
        *headers_cursor, key_prefix,
        [&process_func]([[maybe_unused]] ByteView key, ByteView raw_header) {
            if (raw_header.empty()) throw std::logic_error("empty header in table Headers");
            BlockHeader header;
            ByteView encoded_header{raw_header.data(), raw_header.size()};
            success_or_throw(rlp::decode(encoded_header, header));
            process_func(std::move(header));
        },
        CursorMoveDirection::kForward);

    return count;
}

void write_header(RWTxn& txn, const BlockHeader& header, bool with_header_numbers) {
    write_header_ex(txn, header, with_header_numbers);
}

evmc::bytes32 write_header_ex(RWTxn& txn, const BlockHeader& header, bool with_header_numbers) {
    Bytes value{};
    rlp::encode(value, header);
    auto header_hash = std::bit_cast<evmc_bytes32>(keccak256(value));  // avoid header.hash() because it re-does rlp encoding
    auto key{block_key(header.number, header_hash.bytes)};
    auto skey = to_slice(key);
    auto svalue = to_slice(value);

    auto target = txn.rw_cursor(table::kHeaders);
    target->upsert(skey, svalue);
    if (with_header_numbers) {
        write_header_number(txn, header_hash.bytes, header.number);
    }
    return header_hash;
}

void delete_header(RWTxn& txn, BlockNum block_num, const evmc::bytes32& hash) {
    auto cursor = txn.rw_cursor(table::kHeaders);
    auto key = block_key(block_num, hash.bytes);
    cursor->erase(to_slice(key));
}

std::optional<BlockNum> read_stored_header_number_after(ROTxn& txn, BlockNum min_block_num) {
    auto cursor = txn.ro_cursor(table::kHeaders);
    auto key = block_key(min_block_num);
    auto result = cursor->lower_bound(to_slice(key), /*throw_notfound=*/false);
    if (!result) {
        return std::nullopt;
    }
    return block_num_from_key(result.key);
}

std::optional<BlockHeader> read_canonical_header(ROTxn& txn, BlockNum block_num) {  // also known as read-header-by-number
    std::optional<evmc::bytes32> h = read_canonical_header_hash(txn, block_num);
    if (!h) {
        return std::nullopt;  // not found
    }
    return read_header(txn, block_num, h->bytes);
}

static Bytes header_numbers_key(evmc::bytes32 hash) {
    return {hash.bytes, 32};
}

std::optional<BlockNum> read_block_num(ROTxn& txn, const evmc::bytes32& hash) {
    auto header_number_cursor = txn.ro_cursor(table::kHeaderNumbers);
    auto key = header_numbers_key(hash);
    auto data = header_number_cursor->find(to_slice(key), /*throw_notfound=*/false);
    if (!data) {
        return std::nullopt;
    }
    if (data.value.length() != sizeof(BlockNum)) {
        throw std::length_error("Bad block number size " + std::to_string(data.value.length()) + " in db");
    }
    auto block_num = endian::load_big_u64(static_cast<const unsigned char*>(data.value.data()));
    return block_num;
}

void write_header_number(RWTxn& txn, const uint8_t (&hash)[kHashLength], const BlockNum block_num) {
    auto target = txn.rw_cursor(table::kHeaderNumbers);
    auto value{block_key(block_num)};
    target->upsert({hash, kHashLength}, to_slice(value));
}

void delete_header_number(RWTxn& txn, const evmc::bytes32& hash) {
    auto cursor = txn.rw_cursor(table::kHeaderNumbers);
    auto key = header_numbers_key(hash);
    cursor->erase(to_slice(key));
}

std::optional<intx::uint256> read_total_difficulty(ROTxn& txn, BlockNum block_num, const evmc::bytes32& hash) {
    return read_total_difficulty(txn, block_num, hash.bytes);
}

std::optional<intx::uint256> read_total_difficulty(
    ROTxn& txn,
    BlockNum block_num,
    const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_num, hash)};
    return read_total_difficulty(txn, key);
}

std::optional<intx::uint256> read_total_difficulty(ROTxn& txn, ByteView key) {
    auto cursor = txn.ro_cursor(table::kDifficulty);
    auto data{cursor->find(to_slice(key), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }
    intx::uint256 td{0};
    ByteView data_view{from_slice(data.value)};
    success_or_throw(rlp::decode(data_view, td));
    return td;
}

void write_total_difficulty(RWTxn& txn, const Bytes& key, const intx::uint256& total_difficulty) {
    SILKWORM_ASSERT(key.size() == sizeof(BlockNum) + kHashLength);
    Bytes value{};
    rlp::encode(value, total_difficulty);

    auto target = txn.rw_cursor(table::kDifficulty);
    target->upsert(to_slice(key), to_slice(value));
}

void write_total_difficulty(
    RWTxn& txn,
    BlockNum block_num,
    const uint8_t (&hash)[kHashLength],
    const intx::uint256& total_difficulty) {
    auto key{block_key(block_num, hash)};
    write_total_difficulty(txn, key, total_difficulty);
}

void write_total_difficulty(
    RWTxn& txn,
    BlockNum block_num,
    const evmc::bytes32& hash,
    const intx::uint256& total_difficulty) {
    auto key{block_key(block_num, hash.bytes)};
    write_total_difficulty(txn, key, total_difficulty);
}

std::tuple<BlockNum, evmc::bytes32> read_canonical_head(ROTxn& txn) {
    auto cursor = txn.ro_cursor(table::kCanonicalHashes);
    auto data = cursor->to_last();
    if (!data) return {};
    if (data.key.length() != sizeof(BlockNum)) {
        throw std::length_error("Bad block number size " + std::to_string(data.key.length()) + " in db");
    }
    if (data.value.length() != kHashLength) {
        throw std::length_error("Bad block hash size " + std::to_string(data.value.length()) + " in db");
    }
    evmc::bytes32 hash{};
    std::memcpy(hash.bytes, data.value.data(), kHashLength);
    BlockNum block_num = endian::load_big_u64(static_cast<const unsigned char*>(data.key.data()));
    return {block_num, hash};
}

std::optional<evmc::bytes32> read_canonical_header_hash(ROTxn& txn, BlockNum block_num) {
    auto cursor = txn.ro_cursor(table::kCanonicalHashes);
    auto key{block_key(block_num)};
    auto data{cursor->find(to_slice(key), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }
    if (data.value.length() != kHashLength) {
        throw std::length_error("Bad block hash size " + std::to_string(data.value.length()) + " in db");
    }
    evmc::bytes32 ret{};
    std::memcpy(ret.bytes, data.value.data(), kHashLength);
    return ret;
}

void write_canonical_header(RWTxn& txn, const BlockHeader& header) {
    write_canonical_header_hash(txn, header.hash().bytes, header.number);
}

void write_canonical_header_hash(RWTxn& txn, const uint8_t (&hash)[kHashLength], BlockNum block_num) {
    auto cursor = txn.rw_cursor(table::kCanonicalHashes);
    auto key{block_key(block_num)};
    cursor->upsert(to_slice(key), to_slice(hash));
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
    auto key{block_key(base_id)};
    for (const auto& transaction : transactions) {
        Bytes value{};
        rlp::encode(value, transaction);
        mdbx::slice value_slice{value.data(), value.size()};
        cursor->put(to_slice(key), &value_slice, MDBX_APPEND);
        ++base_id;
        endian::store_big_u64(key.data(), base_id);
    }
}

void read_transactions(ROCursor& txn_table, uint64_t base_id, uint64_t count, std::vector<Transaction>& out) {
    out.resize(count);
    if (count == 0) {
        return;
    }

    auto key{block_key(base_id)};

    uint64_t i{0};
    for (auto data = txn_table.find(to_slice(key), /*throw_notfound=*/false); data.done && i < count;
         data = txn_table.to_next(/*throw_notfound=*/false), ++i) {
        ByteView data_view{from_slice(data.value)};
        success_or_throw(rlp::decode(data_view, out.at(i)));
    }
    SILKWORM_ASSERT(i == count);
}

static void read_rlp_transactions(ROTxn& txn, uint64_t base_id, uint64_t count, std::vector<Bytes>& rlp_txs) {
    rlp_txs.resize(count);
    if (count == 0) {
        return;
    }

    const auto key{block_key(base_id)};
    auto cursor = txn.ro_cursor(table::kBlockTransactions);
    uint64_t i{0};
    for (auto data = cursor->find(to_slice(key), /*throw_notfound=*/false); data.done && i < count;
         data = cursor->to_next(/*throw_notfound=*/false), ++i) {
        rlp_txs[i] = from_slice(data.value);
    }
    SILKWORM_ASSERT(i == count);
}

void delete_transactions(RWTxn& txn, uint64_t base_id, uint64_t count) {
    auto cursor = txn.rw_cursor(table::kBlockTransactions);
    auto first_key = block_key(base_id);
    auto result = cursor->find(to_slice(first_key), /*throw_notfound=*/false);
    for (uint64_t i = 0; result && (i < count); result = cursor->to_next(/*throw_notfound=*/false), ++i) {
        cursor->erase();
    }
}

bool read_block_by_number(ROTxn& txn, BlockNum block_num, bool read_senders, Block& block) {
    auto canonical_hashes_cursor = txn.ro_cursor(table::kCanonicalHashes);
    const Bytes key{block_key(block_num)};
    const auto data{canonical_hashes_cursor->find(to_slice(key), /*throw_notfound=*/false)};
    if (!data) {
        return false;
    }
    if (data.value.length() != kHashLength) {
        throw std::length_error("Bad block hash size " + std::to_string(data.value.length()) + " in db");
    }
    const auto hash_ptr{static_cast<const uint8_t*>(data.value.data())};
    return read_block(txn, std::span<const uint8_t, kHashLength>{hash_ptr, kHashLength}, block_num, read_senders, block);
}

bool read_block(ROTxn& txn, const evmc::bytes32& hash, BlockNum block_num, Block& block) {
    // Read header
    read_header(txn, hash, block_num, block.header);
    // Read body
    return read_body(txn, hash, block_num, block);  // read_senders == false
}

bool read_block(
    ROTxn& txn,
    std::span<const uint8_t, kHashLength> hash,
    BlockNum block_num,
    bool read_senders,
    Block& block) {
    // Read header
    const Bytes key{block_key(block_num, hash)};
    const auto raw_header{read_header_raw(txn, key)};
    if (raw_header.empty()) {
        return false;
    }
    ByteView raw_header_view(raw_header);
    success_or_throw(rlp::decode(raw_header_view, block.header));

    return read_body(txn, key, read_senders, block);
}

size_t read_blocks(ROTxn& txn, BlockNum block_num, std::function<void(Block&)> process_func, bool read_senders) {
    auto bodies_cursor = txn.ro_cursor(table::kBlockBodies);
    auto key_prefix{block_key(block_num)};

    auto count = cursor_for_prefix(
        *bodies_cursor, key_prefix,
        [&process_func, &txn, &block_num, &read_senders](ByteView key, ByteView raw_body) {
            if (raw_body.empty()) throw std::logic_error("empty header in table Headers");
            // read block...
            Block block;
            // ...ommers
            auto body = unwrap_or_throw(decode_stored_block_body(raw_body));
            std::swap(block.ommers, body.ommers);
            // ...transactions
            ensure(body.txn_count > 1, [&]() { return "unexpected txn_count=" + std::to_string(body.txn_count) + " for block_num=" + std::to_string(block_num); });
            read_transactions(txn, body.base_txn_id + 1, body.txn_count - 2, block.transactions);
            // ...senders
            if (!block.transactions.empty() && read_senders) {
                Bytes key_bytes{key.data(), key.size()};  // TODO(canepat) avoid unnecessary copy by changing read_senders API
                parse_senders(txn, key_bytes, block.transactions);
            }
            // ...header
            auto [ref_block_num, hash] = split_block_key(key);
            const bool present = read_header(txn, hash, ref_block_num, block.header);
            auto ref_hash = hash;
            ensure(present, [&]() { return "header not found for body block_num= " + std::to_string(ref_block_num) + ", hash= " + silkworm::to_hex(ref_hash); });
            // invoke handler
            process_func(block);
        },
        CursorMoveDirection::kForward);

    return count;
}

bool read_body(ROTxn& txn, const evmc::bytes32& h, BlockNum block_num, BlockBody& body) {
    return read_body(txn, block_num, h.bytes, /*read_senders=*/false, body);
}

bool read_body(ROTxn& txn, BlockNum block_num, const uint8_t (&hash)[kHashLength], bool read_senders,
               BlockBody& out) {
    auto key{block_key(block_num, hash)};
    return read_body(txn, key, read_senders, out);
}

std::optional<BlockBodyForStorage> read_body_for_storage(ROTxn& txn, const Bytes& key) {
    auto cursor = txn.ro_cursor(table::kBlockBodies);
    auto data{cursor->find(to_slice(key), false)};
    if (!data) {
        return std::nullopt;
    }
    ByteView data_view{from_slice(data.value)};
    auto body{unwrap_or_throw(decode_stored_block_body(data_view))};
    return body;
}

std::optional<Bytes> read_raw_body_for_storage(ROTxn& txn, const Bytes& key) {
    auto cursor = txn.ro_cursor(table::kBlockBodies);
    auto data{cursor->find(to_slice(key), false)};
    if (!data) {
        return std::nullopt;
    }
    return Bytes{from_slice(data.value)};
}

bool read_body(ROTxn& txn, const Bytes& key, bool read_senders, BlockBody& out) {
    auto body_opt = read_body_for_storage(txn, key);
    if (!body_opt) {
        return false;
    }
    BlockBodyForStorage& body = *body_opt;

    std::swap(out.ommers, body.ommers);
    std::swap(out.withdrawals, body.withdrawals);
    ensure(body.txn_count > 1, [&]() { return "unexpected txn_count=" + std::to_string(body.txn_count) + " for key=" + to_hex(key); });
    read_transactions(txn, body.base_txn_id + 1, body.txn_count - 2, out.transactions);
    if (!out.transactions.empty() && read_senders) {
        parse_senders(txn, key, out.transactions);
    }
    return true;
}

bool read_rlp_transactions(ROTxn& txn, BlockNum block_num, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) {
    const auto key{block_key(block_num, hash.bytes)};
    auto body_opt = read_body_for_storage(txn, key);
    if (!body_opt) return false;
    auto& body = *body_opt;

    ensure(body.txn_count > 1, [&]() { return "unexpected txn_count=" + std::to_string(body.txn_count) + " for key=" + std::to_string(block_num); });
    read_rlp_transactions(txn, body.base_txn_id + 1, body.txn_count - 2, rlp_txs);

    return true;
}

bool read_body(ROTxn& txn, const evmc::bytes32& hash, BlockBody& body) {
    auto block_num = read_block_num(txn, hash);
    if (!block_num) {
        return false;
    }
    return read_body(txn, *block_num, hash.bytes, /*read_senders=*/false, body);
}

bool read_canonical_body(ROTxn& txn, BlockNum block_num, bool read_senders, BlockBody& body) {
    auto hash = read_canonical_header_hash(txn, block_num);
    if (!hash) return false;
    return read_body(txn, block_num, hash->bytes, read_senders, body);
}

std::optional<BlockBodyForStorage> read_canonical_body_for_storage(ROTxn& txn, BlockNum block_num) {
    auto hash = read_canonical_header_hash(txn, block_num);
    if (!hash) return std::nullopt;
    return read_body_for_storage(txn, block_key(block_num, hash->bytes));
}

std::optional<Bytes> read_raw_canonical_body_for_storage(ROTxn& txn, BlockNum block_num) {
    auto hash = read_canonical_header_hash(txn, block_num);
    if (!hash) return std::nullopt;
    return read_raw_body_for_storage(txn, block_key(block_num, hash->bytes));
}

bool read_canonical_block(ROTxn& txn, BlockNum block_num, Block& block) {
    std::optional<evmc::bytes32> h = read_canonical_header_hash(txn, block_num);
    if (!h) return false;

    bool present = read_header(txn, *h, block_num, block.header);
    if (!present) return false;

    return read_body(txn, *h, block_num, block);
}

bool has_body(ROTxn& txn, BlockNum block_num, const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_num, hash)};
    auto cursor = txn.ro_cursor(table::kBlockBodies);
    return cursor->find(to_slice(key), false);
}

bool has_body(ROTxn& txn, BlockNum block_num, const evmc::bytes32& hash) {
    return has_body(txn, block_num, hash.bytes);
}

void write_body(RWTxn& txn, const BlockBody& body, const evmc::bytes32& hash, BlockNum block_num) {
    write_body(txn, body, hash.bytes, block_num);
}

void write_body(RWTxn& txn, const BlockBody& body, const uint8_t (&hash)[kHashLength], const BlockNum block_num) {
    BlockBodyForStorage body_for_storage{};
    body_for_storage.ommers = body.ommers;
    body_for_storage.withdrawals = body.withdrawals;
    body_for_storage.txn_count = body.transactions.size() + 2;
    body_for_storage.base_txn_id =
        increment_map_sequence(txn, table::kBlockTransactions.name, body_for_storage.txn_count);
    Bytes value{body_for_storage.encode()};
    auto key{block_key(block_num, hash)};

    auto target = txn.rw_cursor(table::kBlockBodies);
    target->upsert(to_slice(key), to_slice(value));

    write_transactions(txn, body.transactions, body_for_storage.base_txn_id + 1);
}

void write_raw_body(RWTxn& txn, const BlockBody& body, const evmc::bytes32& hash, BlockNum block_num) {
    BlockBodyForStorage body_for_storage{};
    body_for_storage.ommers = body.ommers;
    body_for_storage.withdrawals = body.withdrawals;
    body_for_storage.txn_count = body.transactions.size();
    body_for_storage.base_txn_id =
        increment_map_sequence(txn, table::kBlockTransactions.name, body_for_storage.txn_count);
    Bytes value{body_for_storage.encode()};
    auto key{block_key(block_num, hash.bytes)};

    auto target = txn.rw_cursor(table::kBlockBodies);
    target->upsert(to_slice(key), to_slice(value));

    write_transactions(txn, body.transactions, body_for_storage.base_txn_id);
}

void delete_body(RWTxn& txn, const evmc::bytes32& hash, BlockNum block_num) {
    auto cursor = txn.rw_cursor(table::kBlockBodies);
    auto key = block_key(block_num, hash.bytes);
    cursor->erase(to_slice(key));
}

static ByteView read_senders_raw(ROTxn& txn, const Bytes& key) {
    auto cursor = txn.ro_cursor(table::kSenders);
    auto data{cursor->find(to_slice(key), /*throw_notfound = */ false)};
    return data ? from_slice(data.value) : ByteView();
}

std::vector<evmc::address> read_senders(ROTxn& txn, BlockNum block_num, const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_num, hash)};
    return read_senders(txn, key);
}

std::vector<evmc::address> read_senders(ROTxn& txn, const Bytes& key) {
    std::vector<evmc::address> senders{};
    auto data_view{read_senders_raw(txn, key)};
    if (!data_view.empty()) {
        SILKWORM_ASSERT(data_view.size() % kAddressLength == 0);
        senders.resize(data_view.size() / kAddressLength);
        std::memcpy(senders.data(), data_view.data(), data_view.size());
    }
    return senders;
}

void parse_senders(ROTxn& txn, const Bytes& key, std::vector<Transaction>& out) {
    if (out.empty()) {
        return;
    }
    auto data_view{read_senders_raw(txn, key)};
    if (!data_view.empty()) {
        SILKWORM_ASSERT(data_view.size() % kAddressLength == 0);
        SILKWORM_ASSERT(data_view.size() / kAddressLength == out.size());
        auto addresses = reinterpret_cast<const evmc::address*>(data_view.data());
        size_t idx{0};
        for (auto& transaction : out) {
            transaction.set_sender(addresses[idx++]);
        }
    } else {
        // Might be empty due to pruning
    }
}

void write_senders(RWTxn& txn, const evmc::bytes32& hash, const BlockNum& block_num, const Block& block) {
    auto key{block_key(block_num, hash.bytes)};
    auto target = txn.rw_cursor(table::kSenders);
    Bytes data;
    for (const auto& block_txn : block.transactions) {
        if (const std::optional<evmc::address> sender{block_txn.sender()}; sender) {
            data.append(sender->bytes, kAddressLength);
        } else {
            throw std::runtime_error("Missing senders for block " + std::to_string(block_num));
        }
    }

    target->upsert(to_slice(key), to_slice(data));
}

void delete_senders(RWTxn& txn, const evmc::bytes32& hash, const BlockNum& block_num) {
    auto cursor = txn.rw_cursor(table::kSenders);
    auto key = block_key(block_num, hash.bytes);
    cursor->erase(to_slice(key));
}

void write_tx_lookup(RWTxn& txn, const Block& block) {
    auto target = txn.rw_cursor(table::kTxLookup);
    const auto block_num_bytes = block_key(block.header.number);
    for (const auto& block_txn : block.transactions) {
        auto tx_key = block_txn.hash();
        target->upsert(to_slice(tx_key), to_slice(block_num_bytes));
    }
}

void write_receipts(RWTxn& txn, const std::vector<silkworm::Receipt>& receipts, const BlockNum& block_num) {
    auto target = txn.rw_cursor(table::kBlockReceipts);
    auto key{block_key(block_num)};
    Bytes value{cbor_encode(receipts)};
    target->upsert(to_slice(key), to_slice(value));
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
static std::optional<ByteView> historical_account(ROTxn& txn, const evmc::address& address, BlockNum block_num) {
    auto cursor = txn.ro_cursor_dup_sort(table::kAccountHistory);
    const Bytes history_key{account_history_key(address, block_num)};
    const auto data{cursor->lower_bound(to_slice(history_key), /*throw_notfound=*/false)};
    if (!data || !data.key.starts_with(to_slice(address))) {
        return std::nullopt;
    }

    const auto bitmap{bitmap::parse(data.value)};
    const auto change_block{bitmap::seek(bitmap, block_num)};
    if (!change_block) {
        return std::nullopt;
    }

    cursor->bind(txn, table::kAccountChangeSet);
    const Bytes change_set_key{block_key(*change_block)};
    return find_value_suffix(*cursor, change_set_key, address.bytes);
}

// Erigon FindByHistory for storage
static std::optional<ByteView> historical_storage(ROTxn& txn, const evmc::address& address, uint64_t incarnation,
                                                  const evmc::bytes32& location, BlockNum block_num) {
    auto cursor = txn.ro_cursor_dup_sort(table::kStorageHistory);
    const Bytes history_key{storage_history_key(address, location, block_num)};
    const auto data{cursor->lower_bound(to_slice(history_key), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }

    const ByteView k{from_slice(data.key)};
    SILKWORM_ASSERT(k.size() == kAddressLength + kHashLength + sizeof(BlockNum));

    if (k.substr(0, kAddressLength) != ByteView{address} ||
        k.substr(kAddressLength, kHashLength) != ByteView{location}) {
        return std::nullopt;
    }

    const auto bitmap{bitmap::parse(data.value)};
    const auto change_block{bitmap::seek(bitmap, block_num)};
    if (!change_block) {
        return std::nullopt;
    }

    cursor->bind(txn, table::kStorageChangeSet);
    const Bytes change_set_key{storage_change_key(*change_block, address, incarnation)};
    return find_value_suffix(*cursor, change_set_key, location.bytes);
}

std::optional<Account> read_account(ROTxn& txn, const evmc::address& address, std::optional<BlockNum> block_num) {
    std::optional<ByteView> encoded{block_num.has_value() ? historical_account(txn, address, block_num.value())
                                                          : std::nullopt};

    if (!encoded.has_value()) {
        auto state_cursor = txn.ro_cursor_dup_sort(table::kPlainState);
        if (auto data = state_cursor->find({address.bytes, sizeof(evmc::address)}, /*throw_notfound=*/false); data.done) {
            encoded.emplace(from_slice(data.value));
        }
    }
    if (!encoded.has_value() || encoded->empty()) {
        return std::nullopt;
    }

    const auto acc_res = state::AccountCodec::from_encoded_storage(encoded.value());
    success_or_throw(acc_res);
    Account acc{*acc_res};

    if (acc.incarnation > 0 && acc.code_hash == kEmptyHash) {
        // restore code hash
        auto code_cursor = txn.ro_cursor(table::kPlainCodeHash);
        auto key{storage_prefix(address, acc.incarnation)};
        if (auto data = code_cursor->find(to_slice(key), /*throw_notfound=*/false);
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
        val = find_value_suffix(*cursor, key, location.bytes);
    }

    if (!val.has_value()) {
        return {};
    }

    evmc::bytes32 res{};
    SILKWORM_ASSERT(val->size() <= kHashLength);
    std::memcpy(res.bytes + kHashLength - val->size(), val->data(), val->size());
    return res;
}

static std::optional<uint64_t> historical_previous_incarnation(ROTxn& txn, const evmc::address& address, BlockNum block_num) {
    std::optional<ByteView> encoded_account{historical_account(txn, address, block_num + 1)};
    if (!encoded_account) {
        return std::nullopt;
    }
    const auto acc_result = state::AccountCodec::from_encoded_storage(encoded_account.value());
    success_or_throw(acc_result);
    Account account{*acc_result};
    const uint64_t previous_incarnation{account.incarnation > 0 ? account.incarnation - 1 : 0};
    return previous_incarnation;
}

std::optional<uint64_t> read_previous_incarnation(ROTxn& txn, const evmc::address& address,
                                                  std::optional<BlockNum> block_num) {
    if (block_num.has_value()) {
        return historical_previous_incarnation(txn, address, *block_num);
    }

    auto cursor = txn.ro_cursor(table::kIncarnationMap);
    if (auto data = cursor->find(to_slice(address), /*throw_notfound=*/false); data.done) {
        SILKWORM_ASSERT(data.value.length() == 8);
        const uint64_t previous_incarnation{endian::load_big_u64(static_cast<uint8_t*>(data.value.data()))};
        return previous_incarnation;
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
        changes[address] = from_slice(data.value);
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

        changes[address][incarnation][location] = from_slice(data.value);
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
    auto cursor = txn.rw_cursor(table::kConfig);
    auto config_data{config.to_json().dump()};
    cursor->upsert(to_slice(genesis_hash->bytes), mdbx::slice(config_data.data()));
}

static Bytes head_header_key() {
    std::string table_name = table::kHeadHeader.name;
    Bytes key{table_name.begin(), table_name.end()};
    return key;
}

void write_head_header_hash(RWTxn& txn, const evmc::bytes32& hash) {
    write_head_header_hash(txn, hash.bytes);
}

void write_head_header_hash(RWTxn& txn, const uint8_t (&hash)[kHashLength]) {
    auto target = txn.rw_cursor(table::kHeadHeader);
    Bytes key = head_header_key();
    auto skey = to_slice(key);

    target->upsert(skey, to_slice(hash));
}

std::optional<evmc::bytes32> read_head_header_hash(ROTxn& txn) {
    auto cursor = txn.ro_cursor(table::kHeadHeader);
    Bytes key = head_header_key();
    auto skey = to_slice(key);
    auto data{cursor->find(skey, /*throw_notfound=*/false)};
    if (!data || data.value.length() != kHashLength) {
        return std::nullopt;
    }
    return to_bytes32(from_slice(data.value));
}

void write_canonical_hash(RWTxn& txn, BlockNum block_num, const evmc::bytes32& hash) {
    Bytes key = block_key(block_num);
    auto skey = to_slice(key);
    auto svalue = to_slice(hash);

    auto hashes_cursor = txn.rw_cursor(table::kCanonicalHashes);
    hashes_cursor->upsert(skey, svalue);
}

void delete_canonical_hash(RWTxn& txn, BlockNum block_num) {
    auto hashes_cursor = txn.rw_cursor(table::kCanonicalHashes);
    Bytes key = block_key(block_num);
    auto skey = to_slice(key);
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
    const auto data = target->find(key, /*throw_notfound=*/false);
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

static const std::string kHeadBlockHash = "headBlockHash";
static const std::string kSafeBlockHash = "safeBlockHash";
static const std::string kFinalizedBlockHash = "finalizedBlockHash";

std::optional<evmc::bytes32> read_last_fcu_field(ROTxn& txn, const std::string& field) {
    auto cursor = txn.ro_cursor(table::kLastForkchoice);

    Bytes key{field.begin(), field.end()};
    auto skey = to_slice(key);

    auto data{cursor->find(skey, /*throw_notfound=*/false)};
    if (!data || data.value.length() != kHashLength) {
        return std::nullopt;
    }
    return to_bytes32(from_slice(data.value));
}

void write_last_fcu_field(RWTxn& txn, const std::string& field, const evmc::bytes32& hash) {
    auto cursor = txn.rw_cursor(table::kLastForkchoice);

    Bytes key{field.begin(), field.end()};
    auto skey = to_slice(key);

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

std::optional<ChainConfig> DataModel::read_chain_config() const {
    return db::read_chain_config(txn_);
}

std::optional<ChainId> DataModel::read_chain_id() const {
    const auto chain_config{read_chain_config()};
    std::optional<ChainId> chain_id;
    if (chain_config) {
        chain_id = chain_config->chain_id;
    }
    return chain_id;
}

BlockNum DataModel::max_block_num() const {
    // Assume last block is likely on db: first lookup there
    const auto header_cursor{txn_.ro_cursor(table::kHeaders)};
    const auto data = header_cursor->to_last(/*throw_notfound=*/false);
    if (data.done && data.key.size() >= sizeof(uint64_t)) {
        ByteView key = from_slice(data.key);
        ByteView block_num_data = key.substr(0, sizeof(BlockNum));
        BlockNum block_num = endian::load_big_u64(block_num_data.data());
        if (block_num > 0) {  // skip genesis block if present
            return block_num;
        }
    }

    // If none is found on db, then ask the snapshot repository (if any) for max block
    return repository_.max_timestamp_available();
}

BlockNum DataModel::max_frozen_block_num() const {
    // Ask the snapshot repository (if any) for max block
    return repository_.max_timestamp_available();
}

std::optional<BlockHeader> DataModel::read_header(BlockNum block_num, HashAsArray hash) const {
    return read_header(block_num, Hash(hash));
}

std::optional<BlockHeader> DataModel::read_header(BlockNum block_num, const Hash& hash) const {
    BlockNum repository_max_block_num = repository_.max_timestamp_available();
    if ((repository_max_block_num > 0) && (block_num <= repository_max_block_num)) {
        auto header = read_header_from_snapshot(block_num);
        if (header && header->hash() == hash) {  // reading using hash avoid this heavy hash calculation
            return header;
        }
        return {};
    }
    return db::read_header(txn_, block_num, hash);
}

std::optional<BlockHeader> DataModel::read_header(BlockNum block_num) const {
    BlockNum repository_max_block_num = repository_.max_timestamp_available();
    if ((repository_max_block_num > 0) && (block_num <= repository_max_block_num)) {
        return read_header_from_snapshot(block_num);
    }
    auto hash = db::read_canonical_header_hash(txn_, block_num);
    return db::read_header(txn_, block_num, *hash);
}

std::optional<BlockHeader> DataModel::read_header(const Hash& hash) const {
    // Assume recent blocks are more probable: first lookup the block header in the db
    auto block_header{db::read_header(txn_, hash)};
    if (block_header) return block_header;

    // Then search for it in the snapshots (if any)
    return read_header_from_snapshot(hash);
}

std::pair<std::optional<BlockHeader>, std::optional<Hash>> DataModel::read_head_header_and_hash() const {
    auto hash_opt = read_head_header_hash(txn_);
    if (!hash_opt) return {std::nullopt, std::nullopt};
    Hash hash{*hash_opt};
    auto header = read_header(hash);
    return {std::move(header), hash};
}

std::optional<BlockNum> DataModel::read_block_num(const Hash& hash) const {
    // Assume recent blocks are more probable: first lookup the block in the db
    auto block_num = db::read_block_num(txn_, hash);
    if (block_num) return block_num;

    // Then search for it in the snapshots (if any)
    const auto block_header{read_header_from_snapshot(hash)};
    if (block_header) {
        block_num = block_header->number;
    }
    return block_num;
}

std::vector<BlockHeader> DataModel::read_sibling_headers(BlockNum block_num) const {
    std::vector<BlockHeader> sibling_headers;

    // Read all siblings headers at block_num from db
    read_headers(txn_, block_num, [&](BlockHeader header) {
        sibling_headers.push_back(std::move(header));
    });

    // Read block header at block_num from snapshot (if any) just in case
    std::optional<BlockHeader> header = read_header_from_snapshot(block_num);
    if (header) {
        sibling_headers.push_back(std::move(*header));
    }

    return sibling_headers;
}

bool DataModel::read_body(BlockNum block_num, HashAsArray hash, bool read_senders, BlockBody& body) const {
    // Assume recent blocks are more probable: first lookup the block body in the db
    const bool found = db::read_body(txn_, block_num, hash, read_senders, body);
    if (found) return found;

    return read_body_from_snapshot(block_num, body);
}

bool DataModel::read_body(const Hash& hash, BlockNum block_num, BlockBody& body) const {
    return read_body(block_num, hash.bytes, /*read_senders=*/false, body);
}

bool DataModel::read_body(const Hash& hash, BlockBody& body) const {
    const bool found = db::read_body(txn_, hash, body);
    if (found) return found;

    // Then search for it in the snapshots (if any)
    const auto block_header{read_header_from_snapshot(hash)};
    if (block_header) {
        return read_body(block_header->number, hash.bytes, /*read_senders=*/false, body);
    }

    return false;
}

std::optional<Hash> DataModel::read_canonical_header_hash(BlockNum block_num) const {
    const auto block_hash = db::read_canonical_header_hash(txn_, block_num);
    if (block_hash) return block_hash;

    const auto block_header = read_header_from_snapshot(block_num);
    if (!block_header) return {};

    return block_header->hash();
}

std::optional<BlockHeader> DataModel::read_canonical_header(BlockNum block_num) const {
    // We don't use DataModel::read_canonical_header_hash here to avoid double read for headers in snapshots
    const auto canonical_hash{db::read_canonical_header_hash(txn_, block_num)};
    if (canonical_hash) {
        return db::read_header(txn_, block_num, *canonical_hash);
    }

    return read_header_from_snapshot(block_num);
}

bool DataModel::read_canonical_body(BlockNum block_num, BlockBody& body) const {
    const auto canonical_hash{read_canonical_header_hash(block_num)};
    if (!canonical_hash) return {};

    return read_body(*canonical_hash, block_num, body);
}

bool DataModel::read_canonical_block(BlockNum block_num, Block& block) const {
    const auto canonical_hash = db::read_canonical_header_hash(txn_, block_num);
    if (canonical_hash) {
        const bool found = db::read_block(txn_, *canonical_hash, block_num, block);
        if (found) return found;
    }

    return read_block_from_snapshot(block_num, block);
}

std::optional<Transaction> DataModel::read_transaction_by_txn_idx(BlockNum block_num, uint64_t txn_idx) const {
    std::vector<Transaction> transactions;

    // Assume recent blocks are more probable: first lookup the block body in the db
    if (block_num > max_frozen_block_num() || max_frozen_block_num() == 0) {
        auto hash = read_canonical_header_hash(block_num);
        if (!hash) return std::nullopt;
        const Bytes key{block_key(block_num, hash->bytes)};
        auto body_opt = read_body_for_storage(txn_, key);
        if (body_opt) {
            BlockBodyForStorage& body = *body_opt;
            if (2 + txn_idx >= body_opt->txn_count) {
                return std::nullopt;
            }
            read_transactions(txn_, body.base_txn_id + 1 + txn_idx, /*count=*/1, transactions);
            SILKWORM_ASSERT(!transactions.empty());
            return transactions[0];
        }
    }

    auto stored_body = read_body_for_storage_from_snapshot(block_num);
    if (!stored_body) return std::nullopt;
    if (2 + txn_idx >= stored_body->txn_count) {
        return std::nullopt;
    }

    const auto start_txn_id{stored_body->base_txn_id + 1 + txn_idx};

    const auto read_ok{read_transactions_from_snapshot(block_num, start_txn_id, /*txn_count=*/1, transactions)};
    if (!read_ok) return std::nullopt;

    SILKWORM_ASSERT(!transactions.empty());
    return transactions[0];
}

bool DataModel::has_body(BlockNum block_num, HashAsArray hash) const {
    const bool found = db::has_body(txn_, block_num, hash);
    if (found) return found;

    return is_body_in_snapshot(block_num);
}

bool DataModel::has_body(BlockNum block_num, const Hash& hash) const {
    return has_body(block_num, hash.bytes);
}

bool DataModel::read_block(HashAsSpan hash, BlockNum block_num, bool read_senders, Block& block) const {
    const bool found = db::read_block(txn_, hash, block_num, read_senders, block);
    if (found) return found;

    return read_block_from_snapshot(block_num, block);
}

bool DataModel::read_block(const evmc::bytes32& hash, BlockNum block_num, Block& block) const {
    const bool found = db::read_block(txn_, hash, block_num, block);
    if (found) return found;

    return read_block_from_snapshot(block_num, block);
}

void DataModel::for_last_n_headers(size_t n, absl::FunctionRef<void(BlockHeader)> callback) const {
    const bool throw_notfound{false};

    // Try to read N headers from the database
    size_t read_count{0};
    std::optional<BlockNum> last_read_block_num_from_db;

    const auto headers_cursor{txn_.ro_cursor(table::kHeaders)};
    auto data = headers_cursor->to_last(throw_notfound);
    while (data && read_count < n) {
        // Read header
        BlockHeader header;
        ByteView data_view = from_slice(data.value);
        success_or_throw(rlp::decode(data_view, header));
        ++read_count;
        last_read_block_num_from_db = header.number;
        // Consume header
        callback(std::move(header));
        // Move backward
        data = headers_cursor->to_previous(throw_notfound);
    }
    if (read_count == n) {
        return;
    }

    BlockNum block_num_in_snapshots = repository_.max_timestamp_available();

    // We've reached the first header in db but still need to read more from snapshots
    if (last_read_block_num_from_db > 0) {
        ensure(*last_read_block_num_from_db == block_num_in_snapshots + 1,
               "db and snapshot block numbers are not contiguous");
    }

    while (read_count < n) {
        auto header{read_header_from_snapshot(block_num_in_snapshots)};
        if (!header) return;
        ++block_num_in_snapshots;
        ++read_count;
        // Consume header
        callback(std::move(*header));
    }
}

bool DataModel::read_block(BlockNum block_num, bool read_senders, Block& block) const {
    const auto hash = db::read_canonical_header_hash(txn_, block_num);
    if (hash) {
        const bool found = db::read_block(txn_, hash->bytes, block_num, read_senders, block);
        if (found) return found;
    }

    return read_block_from_snapshot(block_num, block);
}

bool DataModel::read_block_from_snapshot(BlockNum block_num, Block& block) const {
    auto block_header{read_header_from_snapshot(block_num)};
    if (!block_header) return false;

    block.header = std::move(*block_header);

    return read_body_from_snapshot(block_num, block);
}

std::optional<BlockHeader> DataModel::read_header_from_snapshot(BlockNum block_num) const {
    return HeaderFindByBlockNumQuery{repository_}.exec(block_num);
}

std::optional<BlockHeader> DataModel::read_header_from_snapshot(const Hash& hash) const {
    auto result = HeaderFindByHashQuery{repository_}.exec(hash);
    if (!result) return std::nullopt;
    return std::move(result->value);
}

std::optional<BlockBodyForStorage> DataModel::read_canonical_body_for_storage(BlockNum block_num) const {
    auto block_body_for_storage = db::read_canonical_body_for_storage(txn_, block_num);
    if (block_body_for_storage) return block_body_for_storage;

    return read_body_for_storage_from_snapshot(block_num);
}

std::optional<Bytes> DataModel::read_raw_canonical_body_for_storage(BlockNum block_num) const {
    auto block_body_for_storage = db::read_raw_canonical_body_for_storage(txn_, block_num);
    if (block_body_for_storage) return block_body_for_storage;

    return read_raw_body_for_storage_from_snapshot(block_num);
}

std::optional<BlockBodyForStorage> DataModel::read_body_for_storage_from_snapshot(BlockNum block_num) const {
    return BodyFindByBlockNumQuery{repository_}.exec(block_num);
}

std::optional<Bytes> DataModel::read_raw_body_for_storage_from_snapshot(BlockNum block_num) const {
    return RawBodyFindByBlockNumQuery{repository_}.exec(block_num);
}

bool DataModel::read_body_from_snapshot(BlockNum block_num, BlockBody& body) const {
    auto stored_body = read_body_for_storage_from_snapshot(block_num);
    if (!stored_body) return false;

    // Skip first and last *system transactions* in block body
    const auto base_txn_id{stored_body->base_txn_id + 1};
    const auto txn_count{stored_body->txn_count >= 2 ? stored_body->txn_count - 2 : stored_body->txn_count};

    std::vector<Transaction> transactions;
    const auto read_ok{read_transactions_from_snapshot(block_num, base_txn_id, txn_count, transactions)};
    if (!read_ok) return false;

    body.transactions = std::move(transactions);
    body.ommers = std::move(stored_body->ommers);
    body.withdrawals = std::move(stored_body->withdrawals);
    return true;
}

bool DataModel::is_body_in_snapshot(BlockNum block_num) const {
    return BodyFindByBlockNumQuery{repository_}.exec(block_num).has_value();
}

bool DataModel::read_transactions_from_snapshot(BlockNum block_num, uint64_t base_txn_id, uint64_t txn_count, std::vector<Transaction>& txs) const {
    if (txn_count == 0) {
        return true;
    }

    auto txs_opt = TransactionRangeFromIdQuery{repository_}.exec(block_num, base_txn_id, txn_count);
    if (!txs_opt) return false;

    txs = std::move(*txs_opt);
    return true;
}

bool DataModel::read_rlp_transactions_from_snapshot(BlockNum block_num, std::vector<Bytes>& rlp_txs) const {
    auto stored_body = BodyFindByBlockNumQuery{repository_}.exec(block_num);
    if (!stored_body) return false;

    // Skip first and last *system transactions* in block body
    const auto base_txn_id{stored_body->base_txn_id + 1};
    const auto txn_count{stored_body->txn_count >= 2 ? stored_body->txn_count - 2 : stored_body->txn_count};
    if (txn_count == 0) return true;

    auto txs_opt = TransactionPayloadRlpRangeFromIdQuery{repository_}.exec(block_num, base_txn_id, txn_count);
    if (!txs_opt) return false;

    rlp_txs = std::move(*txs_opt);
    return true;
}

bool DataModel::read_rlp_transactions(BlockNum block_num, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const {
    bool found = db::read_rlp_transactions(txn_, block_num, hash, rlp_txs);
    if (found) return true;

    return read_rlp_transactions_from_snapshot(block_num, rlp_txs);
}

std::optional<std::pair<BlockNum, TxnId>> DataModel::read_tx_lookup(const evmc::bytes32& tx_hash) const {
    auto result = read_tx_lookup_from_db(tx_hash);
    if (result) {
        return result;
    }

    return read_tx_lookup_from_snapshot(tx_hash);
}

std::optional<std::pair<BlockNum, TxnId>> DataModel::read_tx_lookup_from_db(const evmc::bytes32& tx_hash) const {
    auto cursor = txn_.ro_cursor(table::kTxLookup);
    const auto data = cursor->find(to_slice(tx_hash), /*throw_notfound=*/false);
    if (!data) {
        return std::nullopt;
    }
    const ByteView data_value = from_slice(data.value);
    if (data_value.size() < 2 * sizeof(uint64_t)) {
        return std::nullopt;
    }
    const BlockNum block_num = endian::load_big_u64(data_value.data());
    const TxnId txn_id = endian::load_big_u64(data_value.data() + sizeof(uint64_t));
    return std::make_pair(block_num, txn_id);
}

std::optional<std::pair<BlockNum, TxnId>> DataModel::read_tx_lookup_from_snapshot(const evmc::bytes32& tx_hash) const {
    TransactionBlockNumByTxnHashQuery query{repository_};
    return query.exec(tx_hash);
}

std::optional<intx::uint256> DataModel::read_total_difficulty(BlockNum block_num, const evmc::bytes32& hash) const {
    return db::read_total_difficulty(txn_, block_num, hash);
}

std::optional<intx::uint256> DataModel::read_total_difficulty(BlockNum block_num, HashAsArray hash) const {
    return db::read_total_difficulty(txn_, block_num, hash);
}

std::optional<intx::uint256> DataModel::read_total_difficulty(ByteView key) const {
    return db::read_total_difficulty(txn_, key);
}

}  // namespace silkworm::db
