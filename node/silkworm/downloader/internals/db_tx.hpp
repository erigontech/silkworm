/*
   Copyright 2021-2022 The Silkworm Authors

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

#ifndef SILKWORM_DB_TX_HPP
#define SILKWORM_DB_TX_HPP

#include <functional>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/cast.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>

#include "cpp20_backport.hpp"
#include "types.hpp"

using namespace silkworm;

// A database
class Db {
  public:
    class ReadOnlyAccess;
    class ReadWriteAccess;

    explicit Db(std::string db_path) {
        db::EnvConfig db_config{db_path};
        // db_config.readonly = false;
        env_ = db::open_env(db_config);
    }

    Db(mdbx::env_managed&& env) : env_{std::move(env)} {}  // low level construction, more silkworm friendly

  private:
    mdbx::env_managed env_;
};

// A read-only access to database - used to enforce in some method signatures the type of access
class Db::ReadOnlyAccess {
  public:
    class Tx;

    ReadOnlyAccess(Db& db) : env_{db.env_} {}
    ReadOnlyAccess(mdbx::env_managed& env) : env_{env} {}  // low level construction, more silkworm friendly
    ReadOnlyAccess(const ReadOnlyAccess& copy) : env_{copy.env_} {}

    Tx start_ro_tx();

  protected:
    // auto start_read() {return env_.start_read();}
    // auto start_write() {return env_.start_write();}
    // auto abort(mdbx::txn_managed& txn) {return txn.abort();};
    // auto commit(mdbx::txn_managed& txn) {return txn.commit();};

    mdbx::env_managed& env_;
};

// A read-write access to database - used to enforce in some method signatures the type of access
class Db::ReadWriteAccess : public Db::ReadOnlyAccess {
  public:
    class Tx;

    ReadWriteAccess(Db& db) : Db::ReadOnlyAccess{db} {}
    ReadWriteAccess(mdbx::env_managed& env)
        : Db::ReadOnlyAccess{env} {}  // low level construction, more silkworm friendly
    ReadWriteAccess(const ReadWriteAccess& copy) : Db::ReadOnlyAccess{copy} {}

    Tx start_tx();
    // improvement: enforce a single read-write tx (as MDBX requires) at compilation time
};

// A db read-only transaction
class Db::ReadOnlyAccess::Tx {
  protected:
    mdbx::txn_managed txn;

    Tx(mdbx::txn_managed&& source) : txn{std::move(source)} {}

  public:
    Tx(Db::ReadOnlyAccess& access) : Tx{access.env_.start_read()} {}
    Tx(const Tx&) = delete;                                   // not copyable
    Tx(Tx&& source) noexcept : txn(std::move(source.txn)) {}  // only movable
    Tx(mdbx::txn& source) : txn{source.start_nested()} {}     // to be more silkworm friendly
    ~Tx() {}                                                  // destroying txn cause abort if not done

    void close() { txn.abort(); }  // a more friendly name for a read-only tx
    void abort() { txn.abort(); }
    void commit() { txn.commit(); }

    mdbx::txn_managed& raw() { return txn; }  // for compatibility reason with other modules

    std::optional<Hash> read_canonical_hash(BlockNum b) {  // throws db exceptions // todo: add to db::access_layer.hpp?
        auto hashes_table = db::open_cursor(txn, db::table::kCanonicalHashes);
        // accessing this table with only b we will get the hash of the canonical block at height b
        auto key = db::block_key(b);
        auto data = hashes_table.find(db::to_slice(key), /*throw_notfound*/ false);
        if (!data) return std::nullopt;  // not found
        assert(data.value.length() == kHashLength);
        return Hash(db::from_slice(data.value));  // copy
    }

    static Bytes head_header_key() {  // todo: add to db::util.h?
        std::string table_name = db::table::kHeadHeader.name;
        Bytes key{table_name.begin(), table_name.end()};
        return key;
    }

    std::optional<Hash> read_head_header_hash() {
        auto ret{db::read_head_header_hash(txn)};
        if (!ret.has_value()) {
            return std::nullopt;
        }
        return Hash(ret.value());
    }

    std::optional<BlockHeader> read_header(BlockNum b, Hash h) { return db::read_header(txn, b, h.bytes); }

    std::optional<BlockHeader> read_canonical_header(BlockNum b) {  // also known as read-header-by-number
        std::optional<Hash> h = read_canonical_hash(b);
        if (!h) {
            return std::nullopt;  // not found
        }
        return read_header(b, *h);
    }

    std::optional<ByteView> read_rlp_encoded_header(BlockNum b, Hash h) {
        auto header_table = db::open_cursor(txn, db::table::kHeaders);
        auto key = db::block_key(b, h.bytes);
        auto data = header_table.find(db::to_slice(key), /*throw_notfound*/ false);
        if (!data) return std::nullopt;
        return db::from_slice(data.value);
    }

    static Bytes header_numbers_key(Hash h) {  // todo: add to db::util.h?
        return {h.bytes, 32};
    }

    std::optional<BlockNum> read_block_num(Hash h) {  // todo: add to db::access_layer.hpp?
        auto blockhashes_table = db::open_cursor(txn, db::table::kHeaderNumbers);
        auto key = header_numbers_key(h);
        auto data = blockhashes_table.find(db::to_slice(key), /*throw_notfound*/ false);
        if (!data) {
            return std::nullopt;
        }
        auto block_num = endian::load_big_u64(static_cast<const unsigned char*>(data.value.data()));
        return block_num;
    }

    std::optional<BlockHeader> read_header(Hash h) {  // todo: add to db::access_layer.hpp?
        auto block_num = read_block_num(h);
        if (!block_num) {
            return std::nullopt;
        }
        return read_header(*block_num, h);
    }

    // todo: is it better to replace this func with cursor_for_count(cursor, const WalkFunc&, size_t max_count,
    // CursorMoveDirection) ?
    void read_headers_in_reverse_order(size_t limit, std::function<void(BlockHeader&&)> callback) {
        auto header_table = db::open_cursor(txn, db::table::kHeaders);

        bool throw_notfound = false;
        size_t read = 0;
        auto data = header_table.to_last(throw_notfound);
        while (data && read < limit) {
            // read header
            BlockHeader header;
            ByteView data_view = db::from_slice(data.value);
            rlp::success_or_throw(rlp::decode(data_view, header));
            read++;
            // consume header
            callback(std::move(header));
            // move backward
            data = header_table.to_previous(throw_notfound);
        }
    }

    [[nodiscard]] bool read_body(const Hash& h, BlockBody& body) {  // todo: add to db::access_layer.hpp?
        auto block_num = read_block_num(h);
        if (!block_num) {
            return false;
        }
        return db::read_body(txn, *block_num, h.bytes, /*read_senders=*/false, body);
    }

    std::optional<intx::uint256> read_total_difficulty(BlockNum b, Hash h) {
        return db::read_total_difficulty(txn, b, h.bytes);
    }

    BlockNum read_stage_progress(const char* stage_name) { return db::stages::read_stage_progress(txn, stage_name); }

    // see Erigon's HeadersUnwind method for the implementation
    std::tuple<BlockNum, Hash> header_with_biggest_td(const std::set<Hash>* bad_headers = nullptr) {
        BlockNum max_block_num = 0;
        Hash max_hash;
        BigInt max_td = 0;

        auto td_cursor = db::open_cursor(txn, db::table::kDifficulty);

        db::WalkFunc find_max = [bad_headers, &max_block_num, &max_hash, &max_td](
                                    const ::mdbx::cursor&, const ::mdbx::cursor::move_result& result) -> bool {
            ByteView key = db::from_slice(result.key);
            ByteView value = db::from_slice(result.value);

            SILKWORM_ASSERT(key.size() == sizeof(BlockNum) + kHashLength);

            Hash hash{key.substr(sizeof(BlockNum))};
            ByteView block_num = key.substr(0, sizeof(BlockNum));

            if (bad_headers && contains(*bad_headers, hash)) return true;  // = continue loop

            BigInt td = 0;
            rlp::success_or_throw(rlp::decode(value, td));

            if (td > max_td) {
                max_td = td;
                max_hash = hash;
                max_block_num = endian::load_big_u64(block_num.data());
            }

            return true;  // = continue loop
        };

        db::cursor_for_each(td_cursor, find_max, db::CursorMoveDirection::Reverse);

        return {max_block_num, max_hash};
    }
};

// A db read-write transaction
class Db::ReadWriteAccess::Tx : public Db::ReadOnlyAccess::Tx {
    using base = Db::ReadOnlyAccess::Tx;

  public:
    Tx(Db::ReadWriteAccess& access) : base{access.env_.start_write()} {}
    Tx(const Tx&) = delete;                                    // not copyable
    Tx(Tx&& source) noexcept : base(std::move(source.txn)) {}  // only movable
    Tx(mdbx::txn& source) : base{source} {}                    // to be more silkworm friendly

    void write_header(const BlockHeader& header, bool with_header_numbers) {
        Bytes encoded_header;
        rlp::encode(encoded_header, header);

        auto header_hash = bit_cast<evmc_bytes32>(keccak256(encoded_header));  // avoid header.hash() re-do rlp encoding
        Bytes key = db::block_key(header.number, header_hash.bytes);
        auto skey = db::to_slice(key);
        auto svalue = db::to_slice(encoded_header);

        auto headers_table = db::open_cursor(txn, db::table::kHeaders);
        headers_table.upsert(skey, svalue);
        headers_table.close();
        if (with_header_numbers) {
            db::write_header_number(txn, header_hash.bytes, header.number);
        }
    }

    void write_head_header_hash(Hash h) {
        Bytes key = head_header_key();
        auto skey = db::to_slice(key);
        auto svalue = db::to_slice(h);

        auto head_header_table = db::open_cursor(txn, db::table::kHeadHeader);
        head_header_table.upsert(skey, svalue);
        head_header_table.close();
    }

    void write_total_difficulty(BlockNum b, Hash h, intx::uint256 td) {
        Bytes encoded_td;
        rlp::encode(encoded_td, td);

        Bytes key = db::block_key(b, h.bytes);
        auto skey = db::to_slice(key);
        auto svalue = db::to_slice(encoded_td);

        auto td_table = db::open_cursor(txn, db::table::kDifficulty);
        td_table.upsert(skey, svalue);
        td_table.close();
    }

    void write_canonical_hash(BlockNum b, Hash h) {
        Bytes key = db::block_key(b);
        auto skey = db::to_slice(key);
        auto svalue = db::to_slice(h);

        auto hashes_table = db::open_cursor(txn, db::table::kCanonicalHashes);
        hashes_table.upsert(skey, svalue);
        hashes_table.close();
    }

    void write_stage_progress(const char* stage_name, BlockNum height) {
        db::stages::write_stage_progress(txn, stage_name, height);
    }

    void delete_canonical_hash(BlockNum b) {
        auto hashes_table = db::open_cursor(txn, db::table::kCanonicalHashes);
        Bytes key = db::block_key(b);
        auto skey = db::to_slice(key);
        (void)hashes_table.erase(skey);
    }
};

// Implementation of some methods
inline auto Db::ReadOnlyAccess::start_ro_tx() -> Tx { return Tx(*this); }

inline auto Db::ReadWriteAccess::start_tx() -> Tx { return Tx(*this); }

#endif  // SILKWORM_DB_TX_HPP
