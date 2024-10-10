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
#include <silkworm/core/common/util.hpp>
#include <silkworm/db/test_util/mock_cursor.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>

namespace silkworm::db::kv::api {

using namespace evmc::literals;  // NOLINT(build/namespaces_literals)

using testing::_;
using testing::InvokeWithoutArgs;
using testing::Return;

static constexpr uint64_t kTestViewId0{3'000'000};
static constexpr uint64_t kTestViewId1{3'000'001};
static constexpr uint64_t kTestViewId2{3'000'002};

static constexpr BlockNum kTestBlockNumber{1'000'000};
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

TEST_CASE("CoherentStateRoot", "[rpc][ethdb][kv][state_cache]") {
    SECTION("CoherentStateRoot::CoherentStateRoot") {
        CoherentStateRoot root;
        CHECK(root.cache.empty());
        CHECK(root.code_cache.empty());
        CHECK(!root.ready);
        CHECK(!root.canonical);
    }
}

TEST_CASE("CoherentCacheConfig", "[rpc][ethdb][kv][state_cache]") {
    SECTION("CoherentCacheConfig::CoherentCacheConfig") {
        CoherentCacheConfig config;
        CHECK(config.max_views == kDefaultMaxViews);
        CHECK(config.with_storage);
        CHECK(config.max_state_keys == kDefaultMaxStateKeys);
        CHECK(config.max_code_keys == kDefaultMaxCodeKeys);
    }
}

StateChangeSet new_batch(uint64_t view_id, BlockNum block_height, const Hash& block_hash,
                         const ListOfBytes& rlp_txs, bool unwind) {
    StateChangeSet state_change_set;
    state_change_set.state_version_id = view_id;

    state_change_set.state_changes.emplace_back(StateChange{
        .direction = unwind ? Direction::kUnwind : Direction::kForward,
        .block_height = block_height,
        .block_hash = block_hash,
        .rlp_txs = rlp_txs,
    });

    return state_change_set;
}

StateChangeSet new_batch_with_upsert(uint64_t view_id, BlockNum block_height, const Hash& block_hash,
                                     const ListOfBytes& rlp_txs, bool unwind) {
    StateChangeSet state_change_set = new_batch(view_id, block_height, block_hash, rlp_txs, unwind);
    StateChange& latest_change = state_change_set.state_changes[0];

    latest_change.account_changes.emplace_back(AccountChange{
        .address = kTestAddress1,
        .incarnation = kTestIncarnation,
        .change_type = Action::kUpsert,
        .data = kTestAccountData,
    });

    return state_change_set;
}

StateChangeSet new_batch_with_upsert_code(uint64_t view_id, BlockNum block_height,
                                          const Hash& block_hash, const ListOfBytes& rlp_txs,
                                          bool unwind, uint64_t num_changes, uint64_t offset = 0) {
    SILKWORM_ASSERT(num_changes <= kTestAddresses.size());
    SILKWORM_ASSERT(num_changes <= kTestCodes.size());
    SILKWORM_ASSERT(offset < num_changes);

    StateChangeSet state_change_set = new_batch(view_id, block_height, block_hash, rlp_txs, unwind);
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

StateChangeSet new_batch_with_delete(uint64_t view_id, BlockNum block_height, const Hash& block_hash,
                                     const ListOfBytes& rlp_txs, bool unwind) {
    StateChangeSet state_change_set = new_batch(view_id, block_height, block_hash, rlp_txs, unwind);
    StateChange& latest_change = state_change_set.state_changes[0];

    latest_change.account_changes.emplace_back(AccountChange{
        .address = kTestAddress1,
        .change_type = Action::kRemove,
    });

    return state_change_set;
}

StateChangeSet new_batch_with_storage(uint64_t view_id, BlockNum block_height,
                                      const Hash& block_hash, const ListOfBytes& tx_rlps,
                                      bool unwind, uint64_t num_storage_changes) {
    SILKWORM_ASSERT(num_storage_changes <= kTestHashedLocations.size());
    SILKWORM_ASSERT(num_storage_changes <= kTestStorageData.size());

    StateChangeSet state_change_set = new_batch(view_id, block_height, block_hash, tx_rlps, unwind);
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

StateChangeSet new_batch_with_code(uint64_t view_id, BlockNum block_height, const evmc::bytes32& block_hash,
                                   const std::vector<Bytes>& tx_rlps, bool unwind, uint64_t num_code_changes) {
    SILKWORM_ASSERT(num_code_changes <= kTestCodes.size());

    StateChangeSet state_change_set = new_batch(view_id, block_height, block_hash, tx_rlps, unwind);
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

struct StateCacheTest : public silkworm::test_util::ContextTestBase {
    void get_and_check_upsert(CoherentStateCache& cache, Transaction& txn, const evmc::address& address,
                              const Bytes& data) {
        std::unique_ptr<StateView> view = cache.get_view(txn);
        CHECK(view != nullptr);
        if (view) {
            const Bytes address_key{address.bytes, kAddressLength};
            const auto value = spawn_and_wait(view->get(address_key));
            CHECK(value.has_value());
            if (value) {
                CHECK(*value == data);
            }
        }
    }

    void get_and_check_code(CoherentStateCache& cache, Transaction& txn, ByteView code) {
        std::unique_ptr<StateView> view = cache.get_view(txn);
        CHECK(view != nullptr);
        if (view) {
            const ethash::hash256 code_hash{keccak256(code)};
            const Bytes code_hash_key{code_hash.bytes, kHashLength};
            const auto value = spawn_and_wait(view->get_code(code_hash_key));
            CHECK(value.has_value());
            if (value) {
                CHECK(*value == code);
            }
        }
    }
};

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::CoherentStateCache", "[rpc][ethdb][kv][state_cache]") {
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
        CoherentCacheConfig config{0, true, kDefaultMaxStateKeys, kDefaultMaxCodeKeys};
        CHECK_THROWS_AS(CoherentStateCache{config}, std::invalid_argument);
    }
}

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::get_view returns no view", "[rpc][ethdb][kv][state_cache]") {
    SECTION("no batch") {
        CoherentStateCache cache;
        test_util::MockTransaction txn;
        EXPECT_CALL(txn, view_id()).WillOnce(Return(kTestViewId0));
        std::unique_ptr<StateView> view = cache.get_view(txn);
        CHECK(view == nullptr);
        CHECK(cache.state_hit_count() == 0);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 0);
        CHECK(cache.state_eviction_count() == 0);
    }

    SECTION("empty batch") {
        CoherentStateCache cache;
        cache.on_new_block(StateChangeSet{});
        CHECK(cache.latest_data_size() == 0);
        test_util::MockTransaction txn;
        EXPECT_CALL(txn, view_id()).WillOnce(Return(kTestViewId0));
        std::unique_ptr<StateView> view = cache.get_view(txn);
        CHECK(view == nullptr);
        CHECK(cache.state_hit_count() == 0);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 0);
        CHECK(cache.state_eviction_count() == 0);
    }
}

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::get_view one view", "[rpc][ethdb][kv][state_cache]") {
    CoherentStateCache cache;

    SECTION("single upsert change batch => search hit") {
        cache.on_new_block(
            new_batch_with_upsert(kTestViewId0, kTestBlockNumber + 0, kTestBlockHash, kTestZeroTxs, /*unwind=*/false));
        cache.on_new_block(
            new_batch_with_upsert(kTestViewId1, kTestBlockNumber + 1, kTestBlockHash, kTestZeroTxs, /*unwind=*/false));
        CHECK(cache.latest_data_size() == 1);

        test_util::MockTransaction txn;
        EXPECT_CALL(txn, view_id()).Times(2).WillRepeatedly(Return(kTestViewId0));

        get_and_check_upsert(cache, txn, kTestAddress1, kTestAccountData);

        CHECK(cache.state_hit_count() == 1);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 1);
        CHECK(cache.state_eviction_count() == 1);
    }

    SECTION("single upsert+code change batch => double search hit") {
        auto batch = new_batch_with_upsert_code(kTestViewId0, kTestBlockNumber, kTestBlockHash, kTestZeroTxs,
                                                /*unwind=*/false, /*num_changes=*/1);
        cache.on_new_block(batch);
        CHECK(cache.latest_data_size() == 1);
        CHECK(cache.latest_code_size() == 1);

        test_util::MockTransaction txn;
        EXPECT_CALL(txn, view_id()).Times(4).WillRepeatedly(Return(kTestViewId0));

        get_and_check_upsert(cache, txn, kTestAddress1, kTestAccountData);

        CHECK(cache.state_hit_count() == 1);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 1);
        CHECK(cache.state_eviction_count() == 0);

        get_and_check_code(cache, txn, kTestCode1);

        CHECK(cache.code_hit_count() == 1);
        CHECK(cache.code_miss_count() == 0);
        CHECK(cache.code_key_count() == 1);
        CHECK(cache.code_eviction_count() == 0);
    }

    SECTION("single delete change batch => search hit") {
        auto batch = new_batch_with_delete(kTestViewId0, kTestBlockNumber, kTestBlockHash, kTestZeroTxs,
                                           /*unwind=*/false);
        cache.on_new_block(batch);
        CHECK(cache.latest_data_size() == 1);

        test_util::MockTransaction txn;
        EXPECT_CALL(txn, view_id()).Times(2).WillRepeatedly(Return(kTestViewId0));

        std::unique_ptr<StateView> view = cache.get_view(txn);
        CHECK(view != nullptr);
        if (view) {
            const Bytes address_key{kTestAddress1.bytes, kAddressLength};
            const auto value1 = spawn_and_wait(view->get(address_key));
            CHECK(value1.has_value());
            if (value1) {
                CHECK(value1->empty());
            }
            CHECK(cache.state_hit_count() == 1);
            CHECK(cache.state_miss_count() == 0);
            CHECK(cache.state_key_count() == 1);
            CHECK(cache.state_eviction_count() == 0);
        }
    }

    SECTION("single storage change batch => search hit") {
        auto batch = new_batch_with_storage(kTestViewId0, kTestBlockNumber, kTestBlockHash, kTestZeroTxs,
                                            /*unwind=*/false, /*num_storage_changes=*/1);
        cache.on_new_block(batch);
        CHECK(cache.latest_data_size() == 1);

        test_util::MockTransaction txn;
        EXPECT_CALL(txn, view_id()).Times(2).WillRepeatedly(Return(kTestViewId0));

        std::unique_ptr<StateView> view = cache.get_view(txn);
        CHECK(view != nullptr);
        if (view) {
            const auto storage_key1 = composite_storage_key(kTestAddress1, kTestIncarnation, kTestHashedLocation1.bytes);
            const auto value = spawn_and_wait(view->get(storage_key1));
            CHECK(value.has_value());
            if (value) {
                CHECK(*value == kTestStorageData1);
            }
            CHECK(cache.state_hit_count() == 1);
            CHECK(cache.state_miss_count() == 0);
            CHECK(cache.state_key_count() == 1);
            CHECK(cache.state_eviction_count() == 0);
        }
    }

    SECTION("single storage change batch => search miss") {
        auto batch = new_batch_with_storage(kTestViewId0, kTestBlockNumber, kTestBlockHash, kTestZeroTxs,
                                            /*unwind=*/false, /*num_storage_changes=*/1);
        cache.on_new_block(batch);
        CHECK(cache.latest_data_size() == 1);

        std::shared_ptr<test_util::MockCursorDupSort> mock_cursor = std::make_shared<test_util::MockCursorDupSort>();
        test_util::MockTransaction txn;
        EXPECT_CALL(txn, view_id()).WillRepeatedly(Return(kTestViewId0));

        std::unique_ptr<StateView> view = cache.get_view(txn);
        CHECK(view != nullptr);
        if (view) {
            EXPECT_CALL(txn, get_one(_, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<Bytes> {
                co_return kTestStorageData2;
            }));

            const auto storage_key2 = composite_storage_key(kTestAddress1, kTestIncarnation, kTestHashedLocation2.bytes);
            const auto value = spawn_and_wait(view->get(storage_key2));
            CHECK(value.has_value());
            if (value) {
                CHECK(*value == kTestStorageData2);
            }
            CHECK(cache.state_hit_count() == 0);
            CHECK(cache.state_miss_count() == 1);
            CHECK(cache.state_key_count() == 1);
            CHECK(cache.state_eviction_count() == 0);
        }
    }

    SECTION("double storage change batch => double search hit") {
        auto batch = new_batch_with_storage(kTestViewId0, kTestBlockNumber, kTestBlockHash, kTestZeroTxs,
                                            /*unwind=*/false, /*num_storage_changes=*/2);
        cache.on_new_block(batch);
        CHECK(cache.latest_data_size() == 2);

        test_util::MockTransaction txn;
        EXPECT_CALL(txn, view_id()).Times(3).WillRepeatedly(Return(kTestViewId0));
        std::unique_ptr<StateView> view = cache.get_view(txn);

        CHECK(view != nullptr);
        if (view) {
            const auto storage_key1 = composite_storage_key(kTestAddress1, kTestIncarnation, kTestHashedLocation1.bytes);
            const auto value1 = spawn_and_wait(view->get(storage_key1));
            CHECK(value1.has_value());
            if (value1) {
                CHECK(*value1 == kTestStorageData1);
            }
            const auto storage_key2 = composite_storage_key(kTestAddress1, kTestIncarnation, kTestHashedLocation2.bytes);
            const auto value2 = spawn_and_wait(view->get(storage_key2));
            CHECK(value2.has_value());
            if (value2) {
                CHECK(*value2 == kTestStorageData2);
            }
            CHECK(cache.state_hit_count() == 2);
            CHECK(cache.state_miss_count() == 0);
            CHECK(cache.state_key_count() == 2);
            CHECK(cache.state_eviction_count() == 0);
        }
    }

    SECTION("single code change batch => search hit") {
        auto batch = new_batch_with_code(kTestViewId0, kTestBlockNumber, kTestBlockHash, kTestZeroTxs,
                                         /*unwind=*/false, /*num_code_changes=*/1);
        cache.on_new_block(batch);
        CHECK(cache.latest_code_size() == 1);

        test_util::MockTransaction txn;
        EXPECT_CALL(txn, view_id()).Times(2).WillRepeatedly(Return(kTestViewId0));

        std::unique_ptr<StateView> view = cache.get_view(txn);
        CHECK(view != nullptr);
        if (view) {
            const ethash::hash256 code_hash{keccak256(kTestCode1)};
            const Bytes code_hash_key{code_hash.bytes, kHashLength};
            const auto value = spawn_and_wait(view->get_code(code_hash_key));
            CHECK(value.has_value());
            if (value) {
                CHECK(*value == kTestCode1);
            }
            CHECK(cache.code_hit_count() == 1);
            CHECK(cache.code_miss_count() == 0);
            CHECK(cache.code_key_count() == 1);
            CHECK(cache.code_eviction_count() == 0);
        }
    }
}

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::get_view two views", "[rpc][ethdb][kv][state_cache]") {
    CoherentStateCache cache;

    SECTION("two single-upsert change batches => two search hits in different views") {
        auto batch1 = new_batch_with_upsert(kTestViewId1, kTestBlockNumber, kTestBlockHash, kTestZeroTxs,
                                            /*unwind=*/false);
        auto batch2 = new_batch_with_upsert(kTestViewId2, kTestBlockNumber, kTestBlockHash, kTestZeroTxs,
                                            /*unwind=*/false);
        cache.on_new_block(batch1);
        cache.on_new_block(batch2);
        CHECK(cache.latest_data_size() == 1);

        test_util::MockTransaction txn1, txn2;
        EXPECT_CALL(txn1, view_id()).Times(2).WillRepeatedly(Return(kTestViewId1));
        EXPECT_CALL(txn2, view_id()).Times(2).WillRepeatedly(Return(kTestViewId2));

        get_and_check_upsert(cache, txn1, kTestAddress1, kTestAccountData);

        CHECK(cache.state_hit_count() == 1);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 1);
        CHECK(cache.state_eviction_count() == 1);

        get_and_check_upsert(cache, txn2, kTestAddress1, kTestAccountData);

        CHECK(cache.state_hit_count() == 2);
        CHECK(cache.state_miss_count() == 0);
        CHECK(cache.state_key_count() == 1);
        CHECK(cache.state_eviction_count() == 1);
    }

    SECTION("two code change batches => two search hits in different views") {
        auto batch1 = new_batch_with_code(kTestViewId1, kTestBlockNumber, kTestBlockHash, kTestZeroTxs,
                                          /*unwind=*/false, /*num_code_changes=*/1);
        auto batch2 = new_batch_with_code(kTestViewId2, kTestBlockNumber, kTestBlockHash, kTestZeroTxs,
                                          /*unwind=*/false, /*num_code_changes=*/2);
        cache.on_new_block(batch1);
        cache.on_new_block(batch2);
        CHECK(cache.latest_code_size() == 2);

        test_util::MockTransaction txn1, txn2;
        EXPECT_CALL(txn1, view_id()).Times(2).WillRepeatedly(Return(kTestViewId1));
        EXPECT_CALL(txn2, view_id()).Times(4).WillRepeatedly(Return(kTestViewId2));

        get_and_check_code(cache, txn1, kTestCode1);

        CHECK(cache.code_hit_count() == 1);
        CHECK(cache.code_miss_count() == 0);
        CHECK(cache.code_key_count() == 2);
        CHECK(cache.code_eviction_count() == 1);

        get_and_check_code(cache, txn2, kTestCode1);
        get_and_check_code(cache, txn2, kTestCode2);

        CHECK(cache.code_hit_count() == 3);
        CHECK(cache.code_miss_count() == 0);
        CHECK(cache.code_key_count() == 2);
        CHECK(cache.code_eviction_count() == 1);
    }
}

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::on_new_block exceed max views", "[rpc][ethdb][kv][state_cache]") {
    const CoherentCacheConfig config;
    const auto kMaxViews{config.max_views};
    CoherentStateCache cache{config};

    // Create as many state views as the maximum allowed number
    for (uint64_t i{0}; i < kMaxViews; ++i) {
        cache.on_new_block(
            new_batch_with_upsert(kTestViewId0 + i, kTestBlockNumber + i, kTestBlockHash, kTestZeroTxs, /*unwind=*/false));
        test_util::MockTransaction txn;
        EXPECT_CALL(txn, view_id()).WillOnce(Return(kTestViewId0 + i));
        CHECK(cache.get_view(txn) != nullptr);
    }

    // Next incoming batch with progressive view ID overflows the state views
    cache.on_new_block(
        new_batch_with_upsert(kTestViewId0 + kMaxViews, kTestBlockNumber, kTestBlockHash, kTestZeroTxs, /*unwind=*/false));
    test_util::MockTransaction txn;
    EXPECT_CALL(txn, view_id()).WillOnce(Return(kTestViewId0 + kMaxViews));
    CHECK(cache.get_view(txn) != nullptr);

    // Oldest state view i.e. state view with id=0 should have been erased
    test_util::MockTransaction txn0;
    EXPECT_CALL(txn0, view_id()).WillOnce(Return(kTestViewId0));
    CHECK(cache.get_view(txn0) == nullptr);
}

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::on_new_block exceed max keys", "[rpc][ethdb][kv][state_cache]") {
    static constexpr uint64_t kMaxKeys = 2u;
    const CoherentCacheConfig config{kDefaultMaxViews, /*with_storage=*/true, kMaxKeys, kMaxKeys};
    CoherentStateCache cache{config};

    // Create as many data and code keys as the maximum allowed number
    cache.on_new_block(new_batch_with_upsert_code(kTestViewId0, kTestBlockNumber, kTestBlockHash, kTestZeroTxs,
                                                  /*unwind=*/false, /*num_changes=*/kMaxKeys));
    CHECK(cache.state_key_count() == kMaxKeys);
    CHECK(cache.code_key_count() == kMaxKeys);
    CHECK(cache.state_eviction_count() == 0);
    CHECK(cache.code_eviction_count() == 0);

    // Next incoming batch with *new keys* overflows the data and code keys
    cache.on_new_block(new_batch_with_upsert_code(kTestViewId1, kTestBlockNumber + 1, kTestBlockHash, kTestZeroTxs,
                                                  /*unwind=*/false, /*num_changes=*/4, /*offset=*/2));
    CHECK(cache.state_key_count() == kMaxKeys);
    CHECK(cache.code_key_count() == kMaxKeys);
    CHECK(cache.state_eviction_count() == kMaxKeys);
    CHECK(cache.code_eviction_count() == kMaxKeys);
}

TEST_CASE_METHOD(StateCacheTest, "CoherentStateCache::on_new_block clear the cache on view ID wrapping", "[rpc][ethdb][kv][state_cache]") {
    const CoherentCacheConfig config;
    const auto kMaxViews{config.max_views};
    CoherentStateCache cache{config};

    // Create as many state views as the maximum allowed number *up to the max view ID*
    const uint64_t max_view_id = std::numeric_limits<uint64_t>::max();
    std::vector<uint64_t> wrapping_view_ids{max_view_id - 4, max_view_id - 3, max_view_id - 2, max_view_id - 1, max_view_id};
    SILKWORM_ASSERT(wrapping_view_ids.size() == kMaxViews);
    for (uint64_t i{0}; i < wrapping_view_ids.size(); ++i) {
        uint64_t view_id = wrapping_view_ids[i];
        cache.on_new_block(
            new_batch_with_upsert(view_id, kTestBlockNumber + i, kTestBlockHash, kTestZeroTxs, /*unwind=*/false));
        test_util::MockTransaction txn;
        EXPECT_CALL(txn, view_id()).WillRepeatedly(Return(view_id));
        CHECK(cache.get_view(txn) != nullptr);
    }

    // Next incoming batch with progressive view ID overflows the state views
    uint64_t next_view_id = wrapping_view_ids.back() + 1;
    cache.on_new_block(
        new_batch_with_upsert(next_view_id, kTestBlockNumber, kTestBlockHash, kTestZeroTxs, /*unwind=*/false));
    test_util::MockTransaction txn;
    EXPECT_CALL(txn, view_id()).WillRepeatedly(Return(next_view_id));
    CHECK(cache.get_view(txn) != nullptr);

    // All previous state views should have been erased
    for (uint64_t i{0}; i < wrapping_view_ids.size(); ++i) {
        uint64_t old_view_id = wrapping_view_ids[i];
        test_util::MockTransaction old_txn;
        EXPECT_CALL(old_txn, view_id()).WillRepeatedly(Return(old_view_id));
        CHECK(cache.get_view(old_txn) == nullptr);
    }
}

}  // namespace silkworm::db::kv::api
