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

#ifndef SILKWORM_DB_TX_HPP
#define SILKWORM_DB_TX_HPP

#include <silkworm/common/endian.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>

#include "types.hpp"

#include <functional>

using namespace silkworm;

// A database
class Db {
  public:
    class ReadOnlyAccess;
    class ReadWriteAccess;

    explicit Db(std::string db_path) {
        db::EnvConfig db_config{db_path};
        //db_config.readonly = false;
        env_ = db::open_env(db_config);
    }

  private:
    mdbx::env_managed env_;
};

// A read-only access to database - used to enforce in some method signatures the type of access
class Db::ReadOnlyAccess {
  public:
    class Tx;

    ReadOnlyAccess(Db& db): env_{db.env_} {}
    ReadOnlyAccess(mdbx::env_managed& env): env_{env} {} // low level construction, more silkworm friendly
    ReadOnlyAccess(const ReadOnlyAccess& copy): env_{copy.env_} {}

    Tx start_ro_tx();

  protected:
    mdbx::env_managed& env_;
};

// A read-write access to database - used to enforce in some method signatures the type of access
class Db::ReadWriteAccess: public Db::ReadOnlyAccess {
  public:
    class Tx;

    ReadWriteAccess(Db& db): Db::ReadOnlyAccess{db} {}
    ReadWriteAccess(mdbx::env_managed& env): Db::ReadOnlyAccess{env} {} // low level construction, more silkworm friendly
    ReadWriteAccess(const ReadWriteAccess& copy): Db::ReadOnlyAccess{copy} {}

    Tx start_tx();
    // improvement: enforce a single read-write tx (as MDBX requires) at compilation time
};

// A db read-only transaction
class Db::ReadOnlyAccess::Tx {
  protected:
    mdbx::txn_managed txn;

    Tx(mdbx::txn_managed&& source): txn{std::move(source)} {}

  public:
    Tx(Db::ReadOnlyAccess& access): Tx{access.env_.start_read()} {}
    Tx(const Tx&) = delete; // not copyable
    Tx(Tx&& source) noexcept: txn(std::move(source.txn)) {} // only movable
    ~Tx() {} // destroying txn cause abort if not done

    void close() {txn.abort();}     // a more friendly name for a read-only tx
    void abort() {txn.abort();}
    void commit() {txn.commit();}

    mdbx::txn_managed& raw() {return txn;}  // for compatibility reason with other modules

    std::optional<Hash> read_canonical_hash(BlockNum b) {  // throws db exceptions // todo: add to db::access_layer.hpp?
        auto hashes_table = db::open_cursor(txn, db::table::kCanonicalHashes);
        // accessing this table with only b we will get the hash of the canonical block at height b
        auto data = hashes_table.find(db::to_slice(db::block_key(b)), /*throw_notfound*/ false);
        if (!data) return std::nullopt;  // not found
        assert(data.value.length() == kHashLength);
        return Hash(db::from_slice(data.value));  // copy
    }

    static Bytes head_header_key() {  // todo: add to db::util.h?
        std::string table_name = db::table::kHeadHeader.name;
        Bytes key{table_name.begin(), table_name.end()};
        return key;
    }

    std::optional<Hash> read_head_header_hash() {  // todo: add to db::access_layer.hpp?
        auto head_header_table = db::open_cursor(txn, db::table::kHeadHeader);
        auto data = head_header_table.find(db::to_slice(head_header_key()), /*throw_notfound*/ false);
        if (!data) return std::nullopt;
        assert(data.value.length() == kHashLength);
        return Hash(db::from_slice(data.value));
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

    void read_headers_in_reverse_order(size_t limit, std::function<void (BlockHeader&&)> callback) {
        auto header_table = db::open_cursor(txn, db::table::kHeaders);

        bool throw_notfound = false;
        size_t read = 0;
        auto data = header_table.to_last(throw_notfound);
        while (data && read < limit) {
            // read header
            BlockHeader header;
            ByteView data_view = db::from_slice(data.value);
            rlp::err_handler(rlp::decode(data_view, header));
            read++;
            // consume header
            callback(std::move(header));
            // move backward
            data = header_table.to_previous(throw_notfound);
        }
    }

    std::optional<BlockBody> read_body(Hash h) {  // todo: add to db::access_layer.hpp?
        auto block_num = read_block_num(h);
        if (!block_num) {
            return std::nullopt;
        }
        bool read_senders = false;
        return db::read_body(txn, *block_num, h.bytes, read_senders);
    }

    std::optional<intx::uint256> read_total_difficulty(BlockNum b, Hash h) {
        return db::read_total_difficulty(txn, b, h.bytes);
    }

    BlockNum read_stage_progress(const char* stage_name) {
        return db::stages::get_stage_progress(txn, stage_name);
    }
};

// A db read-write transaction
class Db::ReadWriteAccess::Tx : public Db::ReadOnlyAccess::Tx {
  public:
    Tx(Db::ReadWriteAccess& access): Db::ReadOnlyAccess::Tx{access.env_.start_write()} {}
    Tx(const Tx&) = delete; // not copyable
    Tx(Tx&& source) noexcept: Db::ReadOnlyAccess::Tx(std::move(source.txn)) {} // only movable

    void write_header(BlockHeader) {
        // in kHeaders table
        throw std::logic_error("not implemented");
        /*
         * data, err2 := rlp.EncodeToBytes(header)
        if err = db.Put(dbutils.HeadersBucket, dbutils.HeaderKey(blockHeight, hash), data); err != nil {
            return fmt.Errorf("[%s] failed to store header: %w", hi.logPrefix, err)
        }
         */
    }

    void write_head_header_hash(Hash h) {
        throw std::logic_error("not implemented");
    }

    void write_total_difficulty(BlockNum b, Hash h, intx::uint256) noexcept(false) {
        throw std::logic_error("not implemented");
    }

    void write_stage_progress(const char* stage_name, BlockNum height) noexcept(false) {
        db::stages::set_stage_progress(txn, stage_name, height);
    }
};


// Implementation of some methods
inline auto Db::ReadOnlyAccess::start_ro_tx() -> Tx {
    return Tx(*this);
}

inline auto Db::ReadWriteAccess::start_tx() -> Tx {
    return Tx(*this);
}


#endif  // SILKWORM_DB_TX_HPP
