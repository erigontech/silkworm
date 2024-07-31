/*
   Copyright 2023 The Silkworm Authors

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

#include "storage_walker.hpp"

#include <memory>
#include <string>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/db/kv/api/base_transaction.hpp>
#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/ethdb/database.hpp>
#include <silkworm/rpc/test_util/dummy_transaction.hpp>

namespace silkworm::rpc {

using db::chain::ChainStorage;
using db::kv::api::BaseTransaction;
using db::kv::api::Cursor;
using db::kv::api::CursorDupSort;
using db::kv::api::KeyValue;

const nlohmann::json empty;
const std::string zeros = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";  // NOLINT

class DummyCursor : public CursorDupSort {
  public:
    explicit DummyCursor(const nlohmann::json& json) : json_{json} {}

    [[nodiscard]] uint32_t cursor_id() const override {
        return 0;
    }

    Task<void> open_cursor(const std::string& table_name, bool /*is_dup_cursor*/) override {
        table_name_ = table_name;
        table_ = json_.value(table_name_, empty);
        itr_ = table_.end();

        co_return;
    }

    Task<void> close_cursor() override {
        table_name_ = "";
        co_return;
    }

    Task<KeyValue> seek(silkworm::ByteView key) override {
        const auto key_ = silkworm::to_hex(key);

        KeyValue out;
        for (itr_ = table_.begin(); itr_ != table_.end(); itr_++) {
            auto actual = key_;
            auto delta = itr_.key().size() - actual.size();
            if (delta > 0) {
                actual += zeros.substr(0, delta);
            }
            if (itr_.key() >= actual) {
                auto kk{*silkworm::from_hex(itr_.key())};
                auto value{*silkworm::from_hex(itr_.value().get<std::string>())};
                out = KeyValue{kk, value};
                break;
            }
        }

        co_return out;
    }

    Task<KeyValue> seek_exact(silkworm::ByteView key) override {
        const nlohmann::json table = json_.value(table_name_, empty);
        const auto& entry = table.value(silkworm::to_hex(key), "");
        auto value{*silkworm::from_hex(entry)};

        auto kv = KeyValue{silkworm::Bytes{key}, value};

        co_return kv;
    }

    Task<KeyValue> next() override {
        KeyValue out;

        if (++itr_ != table_.end()) {
            auto key{*silkworm::from_hex(itr_.key())};
            auto value{*silkworm::from_hex(itr_.value().get<std::string>())};
            out = KeyValue{key, value};
        }

        co_return out;
    }

    Task<KeyValue> previous() override {
        KeyValue out;

        if (--itr_ != table_.begin()) {
            auto key{*silkworm::from_hex(itr_.key())};
            auto value{*silkworm::from_hex(itr_.value().get<std::string>())};
            out = KeyValue{key, value};
        }

        co_return out;
    }

    Task<KeyValue> next_dup() override {
        KeyValue out;

        if (++itr_ != table_.end()) {
            auto key{*silkworm::from_hex(itr_.key())};
            auto value{*silkworm::from_hex(itr_.value().get<std::string>())};
            out = KeyValue{key, value};
        }

        co_return out;
    }

    Task<silkworm::Bytes> seek_both(silkworm::ByteView key, silkworm::ByteView value) override {
        silkworm::Bytes key_{key};
        key_ += value;

        const nlohmann::json table = json_.value(table_name_, empty);
        const auto& entry = table.value(silkworm::to_hex(key_), "");
        auto out{*silkworm::from_hex(entry)};

        co_return out;
    }

    Task<KeyValue> seek_both_exact(silkworm::ByteView key, silkworm::ByteView value) override {
        silkworm::Bytes key_{key};
        key_ += value;

        const nlohmann::json table = json_.value(table_name_, empty);
        const auto& entry = table.value(silkworm::to_hex(key_), "");
        auto out{*silkworm::from_hex(entry)};
        auto kv = KeyValue{silkworm::Bytes{}, out};

        co_return kv;
    }

  private:
    std::string table_name_;
    const nlohmann::json& json_;
    nlohmann::json table_;
    nlohmann::json::iterator itr_;
};

class DummyTransaction : public BaseTransaction {
  public:
    explicit DummyTransaction(const nlohmann::json& json) : BaseTransaction(nullptr), json_{json} {}

    [[nodiscard]] uint64_t tx_id() const override { return 0; }
    [[nodiscard]] uint64_t view_id() const override { return 0; }

    Task<void> open() override {
        co_return;
    }

    Task<std::shared_ptr<Cursor>> cursor(const std::string& table) override {
        auto cursor = std::make_unique<DummyCursor>(json_);
        co_await cursor->open_cursor(table, false);

        co_return cursor;
    }

    Task<std::shared_ptr<CursorDupSort>> cursor_dup_sort(const std::string& table) override {
        auto cursor = std::make_unique<DummyCursor>(json_);
        co_await cursor->open_cursor(table, true);

        co_return cursor;
    }

    std::shared_ptr<silkworm::State> create_state(boost::asio::any_io_executor&, const ChainStorage&, BlockNum) override {
        return nullptr;
    }

    std::shared_ptr<ChainStorage> create_storage() override {
        return nullptr;
    }

    Task<void> close() override {
        co_return;
    }

    Task<db::kv::api::PaginatedTimestamps> index_range(db::kv::api::IndexRangeQuery&& /*query*/) override {
        co_return test::empty_paginated_timestamps();
    }

    Task<db::kv::api::PaginatedKeysValues> history_range(db::kv::api::HistoryRangeQuery&& /*query*/) override {
        co_return test::empty_paginated_keys_and_values();
    }

  private:
    const nlohmann::json& json_;
};

class DummyDatabase : public ethdb::Database {
  public:
    explicit DummyDatabase(const nlohmann::json& json) : json_{json} {}

    Task<std::unique_ptr<db::kv::api::Transaction>> begin() override {
        auto txn = std::make_unique<DummyTransaction>(json_);
        co_return txn;
    }

  private:
    const nlohmann::json& json_;
};

TEST_CASE("StorageWalker::walk_of_storages") {
    WorkerPool pool{1};
    nlohmann::json json;

    json["PlainState"] = {
        {"79a4d418f7887dd4d5123a41b6c8c186686ae8cb", "030207fc08107ee3bbb7bf3a70"},
        {"79a4d492a05cfd836ea0967edb5943161dd041f7", "0d0101010120d6ea9698de278dad2f31566cd744dd75c4e09925b4bb8f041d265012a940797c"},
        {"79a4d492a05cfd836ea0967edb5943161dd041f700000000000000010000000000000000000000000000000000000000000000000000000000000001", "2ac3c1d3e24b45c6c310534bc2dd84b5ed576335"},
        {"79a4d492a05cfd836ea0967edb5943161dd041f700000000000000010000000000000000000000000000000000000000000000000000000000000006", "335a9b3f79dcfefda3295be6f7c7c47f077dbcd9"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea", "0d0101010120925fa7384049febb1eddca32821f1f1d709687628c1cf77ef40ca5013d04bdef"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea00000000000000010000000000000000000000000000000000000000000000000000000000000001", "2ac3c1d3e24b45c6c310534bc2dd84b5ed576335"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea00000000000000010000000000000000000000000000000000000000000000000000000000000003", "1f6ea08600"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea00000000000000010000000000000000000000000000000000000000000000000000000000000006", "9d5a08e7551951a3ca73cd84a6409ef1e77f5abe"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea00000000000000010178b166a1bcfd299a6ce6918f016c8d0c52788988d89f65f5727c2fa97be6e9", "1e80355e00"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea0000000000000001b797965b738ad51ddbf643b315d0421c26972862ca2e64304783dc8930a2b6e8", "ee6b2800"},
        {"79a4d75bd00b1843ec5292217e71dace5e5a7439", "03010107181855facbc200"}};
    json["StorageHistory"] = {
        {"79a4d492a05cfd836ea0967edb5943161dd041f70000000000000000000000000000000000000000000000000000000000000001ffffffffffffffff", "0100000000000000000000003a300000010000004b00000010000000019b"},      // NOLINT
        {"79a4d492a05cfd836ea0967edb5943161dd041f70000000000000000000000000000000000000000000000000000000000000006ffffffffffffffff", "0100000000000000000000003a300000010000004b00000010000000019b"},      // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea0000000000000000000000000000000000000000000000000000000000000001ffffffffffffffff", "0100000000000000000000003a300000010000004800000010000000b9e0"},      // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea0000000000000000000000000000000000000000000000000000000000000003ffffffffffffffff", "0100000000000000000000003a300000010000004b00010010000000d505c5c5"},  // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea0000000000000000000000000000000000000000000000000000000000000006ffffffffffffffff", "0100000000000000000000003a300000010000004800000010000000b9e0"},      // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea0178b166a1bcfd299a6ce6918f016c8d0c52788988d89f65f5727c2fa97be6e9ffffffffffffffff", "0100000000000000000000003a300000010000004b00000010000000c5c5"},      // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981eab797965b738ad51ddbf643b315d0421c26972862ca2e64304783dc8930a2b6e8ffffffffffffffff", "0100000000000000000000003a300000010000004b00000010000000d505"},      // NOLINT
        {"79a4e7d68b82799b9d52609756b86bd18193f2b20000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff", "0100000000000000000000003a300000010000004d0000001000000052ca"}       // NOLINT
    };

    auto database = DummyDatabase{json};
    auto result = boost::asio::co_spawn(pool, database.begin(), boost::asio::use_future);
    auto tx = result.get();
    StorageWalker walker{*tx};

    const BlockNum block_number{0x52a0b3};
    const evmc::bytes32 start_location{};

    nlohmann::json storage({});
    StorageWalker::AccountCollector collector = [&](const evmc::address& address, const silkworm::ByteView loc, const silkworm::ByteView data) {
        auto key = address_to_hex(address);
        storage[key].push_back({{"loc", "0x" + silkworm::to_hex(loc)}, {"data", "0x" + silkworm::to_hex(data)}});

        return true;
    };

    SECTION("collect storage 1") {
        const evmc::address start_address{0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address};
        const uint64_t incarnation{0};

        auto result1 = boost::asio::co_spawn(pool, walker.walk_of_storages(block_number, start_address, start_location, incarnation, collector), boost::asio::use_future);
        result1.get();

        CHECK(storage.empty());
    }

#ifdef notdef
    SECTION("collect storage 2") {
        const evmc::address start_address{0x79a4d492a05cfd836ea0967edb5943161dd041f7_address};
        const uint64_t incarnation{1};

        auto result = boost::asio::co_spawn(pool, walker.walk_of_storages(block_number, start_address, start_location, incarnation, collector), boost::asio::use_future);
        result.get();

        CHECK(storage.size() == 1);
        CHECK(storage == R"({
            "0x79a4d492a05cfd836ea0967edb5943161dd041f7": [
                {
                "data": "0x2ac3c1d3e24b45c6c310534bc2dd84b5ed576335",
                "loc": "0x0000000000000000000000000000000000000000000000000000000000000001"
                },
                {
                "data": "0x335a9b3f79dcfefda3295be6f7c7c47f077dbcd9",
                "loc": "0x0000000000000000000000000000000000000000000000000000000000000006"
                }
            ]
        })"_json);
    }

    SECTION("collect storage 3") {
        const evmc::address start_address{0x79a4d706e4bc7fd8ff9d0593a1311386a7a981ea_address};
        const uint64_t incarnation{1};

        auto result = boost::asio::co_spawn(pool, walker.walk_of_storages(block_number, start_address, start_location, incarnation, collector), boost::asio::use_future);
        result.get();

        CHECK(storage.size() == 1);
        CHECK(storage == R"({
            "0x79a4d706e4bc7fd8ff9d0593a1311386a7a981ea": [
                {
                "data": "0x2ac3c1d3e24b45c6c310534bc2dd84b5ed576335",
                "loc": "0x0000000000000000000000000000000000000000000000000000000000000001"
                },
                {
                "data": "0x1f6ea08600",
                "loc": "0x0000000000000000000000000000000000000000000000000000000000000003"
                },
                {
                "data": "0x9d5a08e7551951a3ca73cd84a6409ef1e77f5abe",
                "loc": "0x0000000000000000000000000000000000000000000000000000000000000006"
                },
                {
                "data": "0x1e80355e00",
                "loc": "0x0178b166a1bcfd299a6ce6918f016c8d0c52788988d89f65f5727c2fa97be6e9"
                },
                {
                "data": "0xee6b2800",
                "loc": "0xb797965b738ad51ddbf643b315d0421c26972862ca2e64304783dc8930a2b6e8"
                }
            ]
        })"_json);
    }
#endif
}

TEST_CASE("StorageWalker::storage_range_at") {
    WorkerPool pool{1};
    nlohmann::json json;

    json["PlainState"] = {
        {"79a4d418f7887dd4d5123a41b6c8c186686ae8cb", "030207fc08107ee3bbb7bf3a70"},
        {"79a4d492a05cfd836ea0967edb5943161dd041f7", "0d0101010120d6ea9698de278dad2f31566cd744dd75c4e09925b4bb8f041d265012a940797c"},
        {"79a4d492a05cfd836ea0967edb5943161dd041f700000000000000010000000000000000000000000000000000000000000000000000000000000001", "2ac3c1d3e24b45c6c310534bc2dd84b5ed576335"},
        {"79a4d492a05cfd836ea0967edb5943161dd041f700000000000000010000000000000000000000000000000000000000000000000000000000000006", "335a9b3f79dcfefda3295be6f7c7c47f077dbcd9"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea", "0d0101010120925fa7384049febb1eddca32821f1f1d709687628c1cf77ef40ca5013d04bdef"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea00000000000000010000000000000000000000000000000000000000000000000000000000000001", "2ac3c1d3e24b45c6c310534bc2dd84b5ed576335"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea00000000000000010000000000000000000000000000000000000000000000000000000000000003", "1f6ea08600"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea00000000000000010000000000000000000000000000000000000000000000000000000000000006", "9d5a08e7551951a3ca73cd84a6409ef1e77f5abe"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea00000000000000010178b166a1bcfd299a6ce6918f016c8d0c52788988d89f65f5727c2fa97be6e9", "1e80355e00"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea0000000000000001b797965b738ad51ddbf643b315d0421c26972862ca2e64304783dc8930a2b6e8", "ee6b2800"},
        {"79a4d75bd00b1843ec5292217e71dace5e5a7439", "03010107181855facbc200"}};
    json["StorageHistory"] = {
        {"79a4d492a05cfd836ea0967edb5943161dd041f70000000000000000000000000000000000000000000000000000000000000001ffffffffffffffff", "0100000000000000000000003a300000010000004b00000010000000019b"},      // NOLINT
        {"79a4d492a05cfd836ea0967edb5943161dd041f70000000000000000000000000000000000000000000000000000000000000006ffffffffffffffff", "0100000000000000000000003a300000010000004b00000010000000019b"},      // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea0000000000000000000000000000000000000000000000000000000000000001ffffffffffffffff", "0100000000000000000000003a300000010000004800000010000000b9e0"},      // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea0000000000000000000000000000000000000000000000000000000000000003ffffffffffffffff", "0100000000000000000000003a300000010000004b00010010000000d505c5c5"},  // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea0000000000000000000000000000000000000000000000000000000000000006ffffffffffffffff", "0100000000000000000000003a300000010000004800000010000000b9e0"},      // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea0178b166a1bcfd299a6ce6918f016c8d0c52788988d89f65f5727c2fa97be6e9ffffffffffffffff", "0100000000000000000000003a300000010000004b00000010000000c5c5"},      // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981eab797965b738ad51ddbf643b315d0421c26972862ca2e64304783dc8930a2b6e8ffffffffffffffff", "0100000000000000000000003a300000010000004b00000010000000d505"},      // NOLINT
        {"79a4e7d68b82799b9d52609756b86bd18193f2b20000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff", "0100000000000000000000003a300000010000004d0000001000000052ca"}       // NOLINT
    };

    auto database = DummyDatabase{json};
    auto result = boost::asio::co_spawn(pool, database.begin(), boost::asio::use_future);
    auto tx = result.get();
    StorageWalker walker{*tx};

    const BlockNum block_number{0x52a0b3};
    const evmc::bytes32 start_location{};

    nlohmann::json storage({});
    StorageWalker::StorageCollector collector = [&](const silkworm::ByteView key, const silkworm::ByteView sec_key, const silkworm::ByteView value) {
        auto val = silkworm::to_hex(value);
        val.insert(0, 64 - val.length(), '0');
        storage["0x" + silkworm::to_hex(sec_key)] = {{"key", "0x" + silkworm::to_hex(key)}, {"value", "0x" + val}};

        return true;
    };

    SECTION("storage range 1") {
        const evmc::address start_address{0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address};

        auto result1 = boost::asio::co_spawn(pool, walker.storage_range_at(block_number, start_address, start_location, 1, collector), boost::asio::use_future);
        result1.get();

        CHECK(storage.empty());
    }

#ifdef notdef
    SECTION("storage range 2") {
        const evmc::address start_address{0x79a4d492a05cfd836ea0967edb5943161dd041f7_address};

        auto result = boost::asio::co_spawn(pool, walker.storage_range_at(block_number, start_address, start_location, 2, collector), boost::asio::use_future);
        result.get();

        CHECK(storage.size() == 2);
        CHECK(storage == R"({
            "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6": {
                "key": "0x0000000000000000000000000000000000000000000000000000000000000001",
                "value": "0x0000000000000000000000002ac3c1d3e24b45c6c310534bc2dd84b5ed576335"
            },
            "0xf652222313e28459528d920b65115c16c04f3efc82aaedc97be59f3f377c0d3f": {
                "key": "0x0000000000000000000000000000000000000000000000000000000000000006",
                "value": "0x000000000000000000000000335a9b3f79dcfefda3295be6f7c7c47f077dbcd9"
            }
        })"_json);
    }

    SECTION("collect storage 3") {
        const evmc::address start_address{0x79a4d706e4bc7fd8ff9d0593a1311386a7a981ea_address};

        auto result = boost::asio::co_spawn(pool, walker.storage_range_at(block_number, start_address, start_location, 5, collector), boost::asio::use_future);
        result.get();

        CHECK(storage.size() == 5);
        CHECK(storage == R"({
            "0x477d78706bc75a762f043cdb6c3392cab01c962c8dd88ebcdb5c4d662efaf081": {
                "key": "0x0178b166a1bcfd299a6ce6918f016c8d0c52788988d89f65f5727c2fa97be6e9",
                "value": "0x0000000000000000000000000000000000000000000000000000001e80355e00"
            },
            "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6": {
                "key": "0x0000000000000000000000000000000000000000000000000000000000000001",
                "value": "0x0000000000000000000000002ac3c1d3e24b45c6c310534bc2dd84b5ed576335"
            },
            "0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b": {
                "key": "0x0000000000000000000000000000000000000000000000000000000000000003",
                "value": "0x0000000000000000000000000000000000000000000000000000001f6ea08600"
            },
            "0xd5d6957d3744ad83db8d89b197327938890e869b1f9cd6f68be6f7eb426edd33": {
                "key": "0xb797965b738ad51ddbf643b315d0421c26972862ca2e64304783dc8930a2b6e8",
                "value": "0x00000000000000000000000000000000000000000000000000000000ee6b2800"
            },
            "0xf652222313e28459528d920b65115c16c04f3efc82aaedc97be59f3f377c0d3f": {
                "key": "0x0000000000000000000000000000000000000000000000000000000000000006",
                "value": "0x0000000000000000000000009d5a08e7551951a3ca73cd84a6409ef1e77f5abe"
            }
        })"_json);
    }
#endif
}

TEST_CASE("make key for address and location") {
    evmc::address address = 0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address;
    evmc::bytes32 location = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;

    auto key = make_key(address, location);
    CHECK(silkworm::to_hex(key) == "79a4d418f7887dd4d5123a41b6c8c186686ae8cb56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
}

}  // namespace silkworm::rpc
