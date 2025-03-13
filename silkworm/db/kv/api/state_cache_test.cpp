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

#include "state_cache.hpp"

#include <chrono>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>

namespace silkworm::db::kv::api {

using namespace std::chrono_literals;
using namespace evmc::literals;  // NOLINT(build/namespaces_literals)

using testing::_;
using testing::InvokeWithoutArgs;

static constexpr uint64_t kTestStateVersionId0{3'000'000};
static constexpr uint64_t kTestStateVersionId1{3'000'001};
static constexpr uint64_t kTestStateVersionId2{3'000'002};

static constexpr BlockNum kTestBlockNum{1'000'000};
static constexpr evmc::bytes32 kTestBlockHash{0x8e38b4dbf6b11fcc3b9dee84fb7986e29ca0a02cecd8977c161ff7333329681e_bytes32};

static constexpr evmc::address kTestAddress1{0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6_address};
static constexpr evmc::address kTestAddress2{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
static constexpr evmc::address kTestAddress3{0x326c977e6efc84e512bb9c30f76e30c160ed06fb_address};
static constexpr evmc::address kTestAddress4{0x2d3be3b6021606e1af02fccbc6ea5b192e6d412d_address};
static const std::vector<evmc::address> kTestAddresses{kTestAddress1, kTestAddress2, kTestAddress3, kTestAddress4};
static constexpr uint64_t kTestIncarnation{3};

static const Bytes kTestAccountData{*from_hex("600035600055")};

static const Bytes kTestStorageData1{*from_hex("600035600055")};
static const Bytes kTestStorageData2{*from_hex("6000356000550055")};
static const std::vector<Bytes> kTestStorageData{kTestStorageData1, kTestStorageData2};

static const Bytes kTestCode1{*from_hex("602a6000556101c960015560068060166000396000f3600035600055")};
static const Bytes kTestCode2{*from_hex("600160010160005500")};
static const Bytes kTestCode3{*from_hex("600260020160005500")};
static const Bytes kTestCode4{*from_hex("60606040526008565b00")};
static const std::vector<Bytes> kTestCodes{kTestCode1, kTestCode2, kTestCode3, kTestCode4};

static const evmc::bytes32 kTestHashedLocation1{0x6677907ab33937e392b9be983b30818f29d594039c9e1e7490bf7b3698888fb1_bytes32};
static const evmc::bytes32 kTestHashedLocation2{0xe046602dcccb1a2f1d176718c8e709a42bba57af2da2379ba7130e2f916c95cd_bytes32};
static const std::vector<evmc::bytes32> kTestHashedLocations{kTestHashedLocation1, kTestHashedLocation2};
static const std::vector<Bytes> kTestZeroTxs{};

TEST_CASE("CoherentStateRoot", "[db][kv][api][state_cache]") {
    SECTION("CoherentStateRoot::CoherentStateRoot") {
        CoherentStateRoot root;
        CHECK(root.cache.empty());
        CHECK(root.code_cache.empty());
        CHECK(!root.ready);
        CHECK(!root.canonical);
    }
}

TEST_CASE("CoherentCacheConfig", "[db][kv][api][state_cache]") {
    SECTION("CoherentCacheConfig::CoherentCacheConfig") {
        CoherentCacheConfig config;
        CHECK(config.max_views == kDefaultMaxViews);
        CHECK(config.with_storage);
        CHECK(config.max_state_keys == kDefaultMaxStateKeys);
        CHECK(config.max_code_keys == kDefaultMaxCodeKeys);
    }
}

static StateChangeSet new_batch(StateVersionId version_id, BlockNum block_num, const Hash& block_hash,
                                const ListOfBytes& rlp_txs, bool unwind) {
    StateChangeSet state_change_set;
    state_change_set.state_version_id = version_id;

    state_change_set.state_changes.emplace_back(StateChange{
        .direction = unwind ? Direction::kUnwind : Direction::kForward,
        .block_num = block_num,
        .block_hash = block_hash,
        .rlp_txs = rlp_txs,
    });

    return state_change_set;
}

static StateChangeSet new_batch_with_upsert(StateVersionId version_id, BlockNum block_num, const Hash& block_hash,
                                            const ListOfBytes& rlp_txs, bool unwind) {
    StateChangeSet state_change_set = new_batch(version_id, block_num, block_hash, rlp_txs, unwind);
    StateChange& latest_change = state_change_set.state_changes[0];

    latest_change.account_changes.emplace_back(AccountChange{
        .address = kTestAddress1,
        .incarnation = kTestIncarnation,
        .change_type = Action::kUpsert,
        .data = kTestAccountData,
    });

    return state_change_set;
}

static StateChangeSet new_batch_with_upsert_code(StateVersionId version_id, BlockNum block_num,
                                                 const Hash& block_hash, const ListOfBytes& rlp_txs,
                                                 bool unwind, uint64_t num_changes, uint64_t offset = 0) {
    SILKWORM_ASSERT(num_changes <= kTestAddresses.size());
    SILKWORM_ASSERT(num_changes <= kTestCodes.size());
    SILKWORM_ASSERT(offset < num_changes);

    StateChangeSet state_change_set = new_batch(version_id, block_num, block_hash, rlp_txs, unwind);
    StateChange& latest_change = state_change_set.state_changes[0];

    for (auto i{offset}; i < num_changes; ++i) {
        latest_change.account_changes.emplace_back(AccountChange{
            .address = kTestAddresses[i],
            .incarnation = kTestIncarnation,
            .change_type = Action::kUpsertCode,
            .data = kTestAccountData,
            .code = kTestCodes[i],
        });
    }

    return state_change_set;
}

static StateChangeSet new_batch_with_delete(StateVersionId version_id, BlockNum block_num, const Hash& block_hash,
                                            const ListOfBytes& rlp_txs, bool unwind) {
    StateChangeSet state_change_set = new_batch(version_id, block_num, block_hash, rlp_txs, unwind);
    StateChange& latest_change = state_change_set.state_changes[0];

    latest_change.account_changes.emplace_back(AccountChange{
        .address = kTestAddress1,
        .change_type = Action::kRemove,
    });

    return state_change_set;
}

static StateChangeSet new_batch_with_storage(uint64_t view_id, BlockNum block_num,
                                             const Hash& block_hash, const ListOfBytes& tx_rlps,
                                             bool unwind, uint64_t num_storage_changes) {
    SILKWORM_ASSERT(num_storage_changes <= kTestHashedLocations.size());
    SILKWORM_ASSERT(num_storage_changes <= kTestStorageData.size());

    StateChangeSet state_change_set = new_batch(view_id, block_num, block_hash, tx_rlps, unwind);
    StateChange& latest_change = state_change_set.state_changes[0];

    StorageChangeSequence storage_change_set;
    for (auto i{0u}; i < num_storage_changes; ++i) {
        storage_change_set.emplace_back(StorageChange{
            .location = kTestHashedLocations[i],
            .data = kTestStorageData[i],
        });
    }

    latest_change.account_changes.emplace_back(AccountChange{
        .address = kTestAddress1,
        .incarnation = kTestIncarnation,
        .change_type = Action::kStorage,
        .storage_changes = std::move(storage_change_set),
    });

    return state_change_set;
}

static StateChangeSet new_batch_with_code(uint64_t view_id, BlockNum block_num, const evmc::bytes32& block_hash,
                                          const std::vector<Bytes>& tx_rlps, bool unwind, uint64_t num_code_changes) {
    SILKWORM_ASSERT(num_code_changes <= kTestCodes.size());

    StateChangeSet state_change_set = new_batch(view_id, block_num, block_hash, tx_rlps, unwind);
    StateChange& latest_change = state_change_set.state_changes[0];

    for (auto i{0u}; i < num_code_changes; ++i) {
        latest_change.account_changes.emplace_back(AccountChange{
            .address = kTestAddress1,
            .change_type = Action::kCode,
            .code = kTestCodes[i],
        });
    }

    return state_change_set;
}

static Bytes state_version_id_bytes(StateVersionId version_id) {
    Bytes version_id_bytes(sizeof(uint64_t), 0);
    endian::store_big_u64(version_id_bytes.data(), version_id);
    return version_id_bytes;
}

struct StateCacheTest : public silkworm::test_util::ContextTestBase {
    Task<std::optional<Bytes>> get_upsert(CoherentStateCache& cache, Transaction& txn, const evmc::address& address) {
        std::unique_ptr<StateView> view = co_await cache.get_view(txn);
        if (!view) co_return std::nullopt;
        const Bytes address_key{address.bytes, kAddressLength};
        const auto value = co_await view->get(address_key);
        if (!value) co_return std::nullopt;
        co_return *value;
    }

    Task<std::optional<Bytes>> get_code(CoherentStateCache& cache, Transaction& txn, ByteView code) {
        std::unique_ptr<StateView> view = co_await cache.get_view(txn);
        if (!view) co_return std::nullopt;
        const ethash::hash256 code_hash{keccak256(code)};
        const Bytes code_hash_key{code_hash.bytes, kHashLength};
        const auto value = co_await view->get_code(code_hash_key);
        if (!value) co_return std::nullopt;
        co_return *value;
    }
};

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::CoherentStateCache", "[db][kv][api][state_cache]") {
    SECTION("default config") {
        CoherentStateCache cache;
        CHECK(cache.latest_data_size() == 0);
        CHECK(cache.latest_code_size() == 0);
        CHECK(cache.state_hit_count() == 0);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 0);
        CHECK(cache.state_eviction_count() == 0);
    }

    SECTION("wrong config") {
        CoherentCacheConfig config{0, /*with_storage=*/true, /*wait_for_new_block*/ true, kDefaultMaxStateKeys, kDefaultMaxCodeKeys};
        CHECK_THROWS_AS(CoherentStateCache{config}, std::invalid_argument);
    }
}

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::get_view returns empty view", "[db][kv][api][state_cache]") {
    CoherentCacheConfig config{.wait_for_new_block = false};
    CoherentStateCache cache{config};

    test_util::MockTransaction txn;
    EXPECT_CALL(txn, get_one(db::table::kSequenceName, string_view_to_byte_view(kPlainStateVersionKey)))
        .WillRepeatedly(InvokeWithoutArgs([&]() -> Task<Bytes> {
            co_return state_version_id_bytes(kTestStateVersionId0);
        }));

    SECTION("no batch") {
        // Must be empty
    }

    SECTION("empty batch") {
        cache.on_new_block(StateChangeSet{});
    }

    CHECK(cache.latest_data_size() == 0);
    CHECK(spawn_and_wait(cache.get_view(txn))->empty());
}

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::get_view one view", "[db][kv][api][state_cache][.]") {
    CoherentCacheConfig config{.block_wait_duration{1ms}};  // keep the block waiting as short as possible
    CoherentStateCache cache{config};

    test_util::MockTransaction txn;
    EXPECT_CALL(txn, get_one(db::table::kSequenceName, string_view_to_byte_view(kPlainStateVersionKey)))
        .WillRepeatedly(InvokeWithoutArgs([&]() -> Task<Bytes> {
            co_return state_version_id_bytes(kTestStateVersionId0);
        }));

    SECTION("single upsert change batch => search hit") {
        cache.on_new_block(
            new_batch_with_upsert(kTestStateVersionId0, kTestBlockNum + 0, kTestBlockHash, kTestZeroTxs, /*unwind=*/false));
        cache.on_new_block(
            new_batch_with_upsert(kTestStateVersionId1, kTestBlockNum + 1, kTestBlockHash, kTestZeroTxs, /*unwind=*/false));
        CHECK(cache.latest_data_size() == 1);

        CHECK(spawn_and_wait(get_upsert(cache, txn, kTestAddress1)) == kTestAccountData);

        CHECK(cache.state_hit_count() == 1);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 1);
        CHECK(cache.state_eviction_count() == 1);
    }

    SECTION("single upsert+code change batch => double search hit") {
        auto batch = new_batch_with_upsert_code(
            kTestStateVersionId0, kTestBlockNum, kTestBlockHash, kTestZeroTxs, /*unwind=*/false, /*num_changes=*/1);
        cache.on_new_block(batch);
        CHECK(cache.latest_data_size() == 1);
        CHECK(cache.latest_code_size() == 1);

        CHECK(spawn_and_wait(get_upsert(cache, txn, kTestAddress1)) == kTestAccountData);

        CHECK(cache.state_hit_count() == 1);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 1);
        CHECK(cache.state_eviction_count() == 0);

        CHECK(spawn_and_wait(get_code(cache, txn, kTestCode1)) == kTestCode1);

        CHECK(cache.code_hit_count() == 1);
        CHECK(cache.code_miss_count() == 0);
        CHECK(cache.code_key_count() == 1);
        CHECK(cache.code_eviction_count() == 0);
    }

    SECTION("single delete change batch => search hit") {
        auto batch = new_batch_with_delete(
            kTestStateVersionId0, kTestBlockNum, kTestBlockHash, kTestZeroTxs, /*unwind=*/false);
        cache.on_new_block(batch);
        CHECK(cache.latest_data_size() == 1);

        std::unique_ptr<StateView> view = spawn_and_wait(cache.get_view(txn));
        REQUIRE(view);
        const Bytes address_key{kTestAddress1.bytes, kAddressLength};
        const auto value1 = spawn_and_wait(view->get(address_key));
        REQUIRE(value1);
        CHECK(value1->empty());
        CHECK(cache.state_hit_count() == 1);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 1);
        CHECK(cache.state_eviction_count() == 0);
    }

    SECTION("single storage change batch => search hit") {
        auto batch = new_batch_with_storage(
            kTestStateVersionId0, kTestBlockNum, kTestBlockHash, kTestZeroTxs, /*unwind=*/false, /*num_storage_changes=*/1);
        cache.on_new_block(batch);
        CHECK(cache.latest_data_size() == 1);

        std::unique_ptr<StateView> view = spawn_and_wait(cache.get_view(txn));
        REQUIRE(view);
        const auto storage_key1 = composite_storage_key(kTestAddress1, kTestIncarnation, kTestHashedLocation1.bytes);
        const auto value = spawn_and_wait(view->get(storage_key1));
        REQUIRE(value == kTestStorageData1);
        CHECK(cache.state_hit_count() == 1);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 1);
        CHECK(cache.state_eviction_count() == 0);
    }

    SECTION("single storage change batch => search miss") {
        auto batch = new_batch_with_storage(
            kTestStateVersionId0, kTestBlockNum, kTestBlockHash, kTestZeroTxs, /*unwind=*/false, /*num_storage_changes=*/1);
        cache.on_new_block(batch);
        CHECK(cache.latest_data_size() == 1);

        /*EXPECT_CALL(txn, get_latest(_))
            .WillOnce(InvokeWithoutArgs([&]() -> Task<GetLatestResult> {
                co_return GetLatestResult{.success = true, .value = kTestStorageData2};
            }));

        std::unique_ptr<StateView> view = spawn_and_wait(cache.get_view(txn));
        REQUIRE(view);

        const auto storage_key2 = composite_storage_key(kTestAddress1, kTestIncarnation, kTestHashedLocation2.bytes);
        const auto value = spawn_and_wait(view->get(storage_key2));
        REQUIRE(value == kTestStorageData2);
        CHECK(cache.state_hit_count() == 0);
        CHECK(cache.state_miss_count() == 1);
        CHECK(cache.state_key_count() == 1);
        CHECK(cache.state_eviction_count() == 0);*/
    }

    SECTION("double storage change batch => double search hit") {
        auto batch = new_batch_with_storage(
            kTestStateVersionId0, kTestBlockNum, kTestBlockHash, kTestZeroTxs, /*unwind=*/false, /*num_storage_changes=*/2);
        cache.on_new_block(batch);
        CHECK(cache.latest_data_size() == 2);

        std::unique_ptr<StateView> view = spawn_and_wait(cache.get_view(txn));
        REQUIRE(view);
        const auto storage_key1 = composite_storage_key(kTestAddress1, kTestIncarnation, kTestHashedLocation1.bytes);
        const auto value1 = spawn_and_wait(view->get(storage_key1));
        REQUIRE(value1 == kTestStorageData1);
        const auto storage_key2 = composite_storage_key(kTestAddress1, kTestIncarnation, kTestHashedLocation2.bytes);
        const auto value2 = spawn_and_wait(view->get(storage_key2));
        REQUIRE(value2 == kTestStorageData2);
        CHECK(cache.state_hit_count() == 2);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 2);
        CHECK(cache.state_eviction_count() == 0);
    }

    SECTION("single code change batch => search hit") {
        auto batch = new_batch_with_code(
            kTestStateVersionId0, kTestBlockNum, kTestBlockHash, kTestZeroTxs, /*unwind=*/false, /*num_code_changes=*/1);
        cache.on_new_block(batch);
        CHECK(cache.latest_code_size() == 1);

        std::unique_ptr<StateView> view = spawn_and_wait(cache.get_view(txn));
        REQUIRE(view);
        const ethash::hash256 code_hash{keccak256(kTestCode1)};
        const Bytes code_hash_key{code_hash.bytes, kHashLength};
        const auto value = spawn_and_wait(view->get_code(code_hash_key));
        REQUIRE(value == kTestCode1);
        CHECK(cache.code_hit_count() == 1);
        CHECK(cache.code_miss_count() == 0);
        CHECK(cache.code_key_count() == 1);
        CHECK(cache.code_eviction_count() == 0);
    }
}

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::get_view two views", "[db][kv][api][state_cache]") {
    CoherentCacheConfig config{.block_wait_duration{1ms}};  // keep the block waiting as short as possible
    CoherentStateCache cache{config};

    test_util::MockTransaction txn1, txn2;
    EXPECT_CALL(txn1, get_one(db::table::kSequenceName, string_view_to_byte_view(kPlainStateVersionKey)))
        .WillRepeatedly(InvokeWithoutArgs([&]() -> Task<Bytes> {
            co_return state_version_id_bytes(kTestStateVersionId1);
        }));
    EXPECT_CALL(txn2, get_one(db::table::kSequenceName, string_view_to_byte_view(kPlainStateVersionKey)))
        .WillRepeatedly(InvokeWithoutArgs([&]() -> Task<Bytes> {
            co_return state_version_id_bytes(kTestStateVersionId2);
        }));

    SECTION("two single-upsert change batches => two search hits in different views") {
        auto batch1 = new_batch_with_upsert(kTestStateVersionId1, kTestBlockNum, kTestBlockHash, kTestZeroTxs,
                                            /*unwind=*/false);
        auto batch2 = new_batch_with_upsert(kTestStateVersionId2, kTestBlockNum, kTestBlockHash, kTestZeroTxs,
                                            /*unwind=*/false);
        cache.on_new_block(batch1);
        cache.on_new_block(batch2);
        CHECK(cache.latest_data_size() == 1);

        CHECK(spawn_and_wait(get_upsert(cache, txn1, kTestAddress1)) == kTestAccountData);

        CHECK(cache.state_hit_count() == 1);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 1);
        CHECK(cache.state_eviction_count() == 1);

        CHECK(spawn_and_wait(get_upsert(cache, txn2, kTestAddress1)) == kTestAccountData);

        CHECK(cache.state_hit_count() == 2);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 1);
        CHECK(cache.state_eviction_count() == 1);
    }

    SECTION("two code change batches => two search hits in different views") {
        auto batch1 = new_batch_with_code(kTestStateVersionId1, kTestBlockNum, kTestBlockHash, kTestZeroTxs,
                                          /*unwind=*/false, /*num_code_changes=*/1);
        auto batch2 = new_batch_with_code(kTestStateVersionId2, kTestBlockNum, kTestBlockHash, kTestZeroTxs,
                                          /*unwind=*/false, /*num_code_changes=*/2);
        cache.on_new_block(batch1);
        cache.on_new_block(batch2);
        CHECK(cache.latest_code_size() == 2);

        CHECK(spawn_and_wait(get_code(cache, txn1, kTestCode1)) == kTestCode1);

        CHECK(cache.code_hit_count() == 1);
        CHECK(cache.code_miss_count() == 0);
        CHECK(cache.code_key_count() == 2);
        CHECK(cache.code_eviction_count() == 1);

        CHECK(spawn_and_wait(get_code(cache, txn2, kTestCode1)) == kTestCode1);
        CHECK(spawn_and_wait(get_code(cache, txn2, kTestCode2)) == kTestCode2);

        CHECK(cache.code_hit_count() == 3);
        CHECK(cache.code_miss_count() == 0);
        CHECK(cache.code_key_count() == 2);
        CHECK(cache.code_eviction_count() == 1);
    }
}

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::on_new_block exceed max views", "[db][kv][api][state_cache]") {
    const CoherentCacheConfig config{.block_wait_duration{1ms}};  // keep the block waiting as short as possible
    const auto max_views{config.max_views};
    CoherentStateCache cache{config};

    // Create as many state views as the maximum allowed number
    for (uint64_t i{0}; i < max_views; ++i) {
        cache.on_new_block(
            new_batch_with_upsert(kTestStateVersionId0 + i, kTestBlockNum + i, kTestBlockHash, kTestZeroTxs, /*unwind=*/false));
        test_util::MockTransaction txn;
        EXPECT_CALL(txn, get_one(db::table::kSequenceName, string_view_to_byte_view(kPlainStateVersionKey)))
            .WillOnce(InvokeWithoutArgs([i]() -> Task<Bytes> {
                co_return state_version_id_bytes(kTestStateVersionId0 + i);
            }));
        CHECK_FALSE(spawn_and_wait(cache.get_view(txn))->empty());
    }

    // Next incoming batch with progressive view ID overflows the state views
    cache.on_new_block(
        new_batch_with_upsert(kTestStateVersionId0 + max_views, kTestBlockNum, kTestBlockHash, kTestZeroTxs, /*unwind=*/false));
    test_util::MockTransaction txn;
    EXPECT_CALL(txn, get_one(db::table::kSequenceName, string_view_to_byte_view(kPlainStateVersionKey)))
        .WillOnce(InvokeWithoutArgs([&]() -> Task<Bytes> {
            co_return state_version_id_bytes(kTestStateVersionId0 + max_views);
        }));
    CHECK_FALSE(spawn_and_wait(cache.get_view(txn))->empty());

    // Oldest state view i.e. state view with id=0 should have been erased
    test_util::MockTransaction txn0;
    EXPECT_CALL(txn0, get_one(db::table::kSequenceName, string_view_to_byte_view(kPlainStateVersionKey)))
        .WillOnce(InvokeWithoutArgs([&]() -> Task<Bytes> {
            co_return state_version_id_bytes(kTestStateVersionId0);
        }));
    CHECK(spawn_and_wait(cache.get_view(txn0))->empty());
}

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::on_new_block exceed max keys", "[db][kv][api][state_cache]") {
    static constexpr uint64_t kMaxKeys = 2u;
    const CoherentCacheConfig config{
        .max_views = kDefaultMaxViews,
        .with_storage = true,
        .wait_for_new_block = true,
        .max_state_keys = kMaxKeys,
        .max_code_keys = kMaxKeys,
        .block_wait_duration = 1ms};
    CoherentStateCache cache{config};

    // Create as many data and code keys as the maximum allowed number
    cache.on_new_block(new_batch_with_upsert_code(kTestStateVersionId0, kTestBlockNum, kTestBlockHash, kTestZeroTxs,
                                                  /*unwind=*/false, /*num_changes=*/kMaxKeys));
    CHECK(cache.state_key_count() == kMaxKeys);
    CHECK(cache.code_key_count() == kMaxKeys);
    CHECK(cache.state_eviction_count() == 0);
    CHECK(cache.code_eviction_count() == 0);

    // Next incoming batch with *new keys* overflows the data and code keys
    cache.on_new_block(new_batch_with_upsert_code(kTestStateVersionId1, kTestBlockNum + 1, kTestBlockHash, kTestZeroTxs,
                                                  /*unwind=*/false, /*num_changes=*/4, /*offset=*/2));
    CHECK(cache.state_key_count() == kMaxKeys);
    CHECK(cache.code_key_count() == kMaxKeys);
    CHECK(cache.state_eviction_count() == kMaxKeys);
    CHECK(cache.code_eviction_count() == kMaxKeys);
}

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::on_new_block clear the cache on view ID wrapping", "[db][kv][api][state_cache]") {
    const CoherentCacheConfig config{.block_wait_duration{1ms}};  // keep the block waiting as short as possible
    const auto max_views{config.max_views};
    CoherentStateCache cache{config};

    // Create as many state views as the maximum allowed with versions *up to the max version ID*
    const uint64_t max_version_id = std::numeric_limits<StateVersionId>::max();
    std::vector<StateVersionId> wrapping_version_ids{max_version_id - 4, max_version_id - 3, max_version_id - 2, max_version_id - 1, max_version_id};
    SILKWORM_ASSERT(wrapping_version_ids.size() == max_views);
    for (uint64_t i{0}; i < wrapping_version_ids.size(); ++i) {
        const StateVersionId version_id = wrapping_version_ids[i];
        cache.on_new_block(
            new_batch_with_upsert(version_id, kTestBlockNum + i, kTestBlockHash, kTestZeroTxs, /*unwind=*/false));
        test_util::MockTransaction txn;
        EXPECT_CALL(txn, get_one(db::table::kSequenceName, string_view_to_byte_view(kPlainStateVersionKey)))
            .WillOnce(InvokeWithoutArgs([version_id]() -> Task<Bytes> {
                co_return state_version_id_bytes(version_id);
            }));
        CHECK_FALSE(spawn_and_wait(cache.get_view(txn))->empty());
    }

    // Next incoming batch with progressive version ID overflows the state versions
    const uint64_t next_version_id = wrapping_version_ids.back() + 1;
    cache.on_new_block(
        new_batch_with_upsert(next_version_id, kTestBlockNum, kTestBlockHash, kTestZeroTxs, /*unwind=*/false));
    test_util::MockTransaction txn;
    EXPECT_CALL(txn, get_one(db::table::kSequenceName, string_view_to_byte_view(kPlainStateVersionKey)))
        .WillOnce(InvokeWithoutArgs([next_version_id]() -> Task<Bytes> {
            co_return state_version_id_bytes(next_version_id);
        }));
    CHECK_FALSE(spawn_and_wait(cache.get_view(txn))->empty());

    // All previous state views should have been erased
    for (uint64_t i{0}; i < wrapping_version_ids.size(); ++i) {
        const StateVersionId old_version_id = wrapping_version_ids[i];
        test_util::MockTransaction old_txn;
        EXPECT_CALL(old_txn, get_one(db::table::kSequenceName, string_view_to_byte_view(kPlainStateVersionKey)))
            .WillOnce(InvokeWithoutArgs([old_version_id]() -> Task<Bytes> {
                co_return state_version_id_bytes(old_version_id);
            }));
        CHECK(spawn_and_wait(cache.get_view(old_txn))->empty());
    }
}

}  // namespace silkworm::db::kv::api
