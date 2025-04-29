// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "debug_api.hpp"

#include <stdexcept>
#include <string>

#include <boost/asio/co_spawn.hpp>
#if !defined(__clang__)
#include <boost/asio/use_future.hpp>
#endif  // !defined(__clang__)
#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/db/kv/api/endpoint/paginated_sequence.hpp>
#include <silkworm/db/kv/api/endpoint/temporal_range.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#if !defined(__clang__)
#include <silkworm/db/tables.hpp>
#endif  // !defined(__clang__)
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/rpc/core/filter_storage.hpp>
#if !defined(__clang__)
#include <silkworm/rpc/stagedsync/stages.hpp>
#endif  // !defined(__clang__)
#include <silkworm/rpc/test_util/dummy_transaction.hpp>

namespace silkworm::rpc::commands {

using testing::Unused;
using namespace evmc::literals;

using PaginatedKV = db::kv::api::PaginatedSequencePair<Bytes, Bytes>;
using PaginatorKV = PaginatedKV::Paginator;
using PageResultKV = PaginatedKV::PageResult;

#ifndef SILKWORM_SANITIZE
TEST_CASE("DebugRpcApi") {
    boost::asio::io_context ioc;
    add_shared_service(ioc, std::make_shared<BlockCache>());
    add_shared_service<db::kv::api::StateCache>(ioc, std::make_shared<db::kv::api::CoherentStateCache>());
    WorkerPool workers{1};

    SECTION("CTOR") {
        CHECK_THROWS_AS(DebugRpcApi(ioc, workers), std::logic_error);
    }
}

// Exclude on MSVC due to error LNK2001: unresolved external symbol testing::Matcher<class std::basic_string_view...
// See also https://github.com/google/googletest/issues/4357
#if !defined(__clang__) && !defined(_WIN32)
using testing::_;
using testing::Invoke;
using testing::InvokeWithoutArgs;

TEST_CASE("get_modified_accounts") {
    WorkerPool pool{1};
    nlohmann::json json;

    json["SyncStage"] = {
        {silkworm::to_hex(rpc::stages::kExecution), "000000000052a060"}};
    json["AccountChangeSet"] = {
        {"000000000052a010", "07aaec0b237ccf56b03a7c43c1c7a783da5606420501010101"},                        // NOLINT
        {"000000000052a011", "0c7b6617b9bc0d20f4030ee079d355246246ef7003010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a012", "15b1281f4e58215b2c3243d864bdf8b9dddc0da2050306abd50101"},                    // NOLINT
        {"000000000052a013", "1a99fb83141a5129a79ed062f6b643b0d4f4770e03023a63088b0bd6d38692a000"},        // NOLINT
        {"000000000052a014", "1b6bf510562cc62b28d23267ab1477dc936405bc030104080dddacfb863133ec"},          // NOLINT
        {"000000000052a015", "209d9af3b5c8fa05d0663db92863ebff7a2f1fff0301040707e169a3f47592"},            // NOLINT
        {"000000000052a016", "22ea9f6b28db76a7162054c05ed812deb2f519cd03030933df0a24e57b4081481edb79d9"},  // NOLINT
        {"000000000052a017", "29f030109f19ff6ee9da1257c96620e50725617c03010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a018", "2d734d0528bc9fb2722eb639dd3ecd1ece09b69e03010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a019", "300e056ec74f9c1189a5cbb22ba46db848d8934c02072386f26fc10000"},                // NOLINT
        {"000000000052a01a", "30d9ed9054681c56bf3cff638b4f3109ed06339a0501010101"},                        // NOLINT
        {"000000000052a01b", "311f29bf022343f621278cb3cc8137f8f14ead0903010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a01c", "329254a40454288f4425220aa6c4173097025e93020708e1bc9bf04000"},                // NOLINT
        {"000000000052a01d", "3432169802ba50d1a2bdbb012cfc449bc4f92c810301620901be9023b33ee9cef7"},        // NOLINT
        {"000000000052a01e", "3546ff99566fadff510fa0befa5b6279e6bc54b903010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a01f", "43966453636059ae8b30678b0475550fa53d9eba03010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a020", "44bb73af73388f6c21f2ce8acda594172897d125"},                                  // NOLINT
        {"000000000052a021", "4a3a65a271c40fb77ecfd032e0e15a12f975af7b03010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a022", "4f980a3ef05eaf6eb2395d8a48594b08502b90330302bb7d08037044be650c8c00"},        // NOLINT
        {"000000000052a023", "4faa6c7f9ef1c3b575a4075ed4504108a7020ed003010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a024", "50d1443617147cf86f88296780574b40075139a5"},                                  // NOLINT
        {"000000000052a025", "5c3f649ffdbc91a247ac45fc2c4c63f9319e5135030305ce1608ea00de3441ad5de1"},      // NOLINT
        {"000000000052a026", "5c954304085df2c17b9931b32129c42f894133dc"},                                  // NOLINT
        {"000000000052a027", "6eec6a64fb1202e0d3fb3b3e6a3793f13df5cf61"},                                  // NOLINT
        {"000000000052a028", "71b4daebdab8779a98343981a9a574366f45ee6b030102070103526b4a6719"},            // NOLINT
        {"000000000052a029", "79a4d418f7887dd4d5123a41b6c8c186686ae8cb030207e808160e36987c569a18"},        // NOLINT
        {"000000000052a02a", "7ae250731360126a6f427a55c464134c3d2a980603010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a02b", "80a79aac8921189f330db4f2e11f9653dde41ce2030103070e61b854e32c00"},            // NOLINT
        {"000000000052a02c", "8348b5cd154ad11142353bf456a64bd15fe83a8603010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a02d", "88231b2c9e726682d0282602fe33c38388cd89b203010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a02e", "884173ac82bad835f297d54a2a71a369efe699b9030103070e61b854e32c00"},            // NOLINT
        {"000000000052a02f", "8a555368749434957ea005ce23a61d41277bd8ab03010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a030", "8dde3d034d5b77ab3102f2626310f63821226a1c03010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a031", "901e370c28193fa207f2a6a515c18756db9557f7030102080ddf6b01cd538869"},          // NOLINT
        {"000000000052a032", "9a46a5638e41398310908b9194c89dd68582e12d03010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a033", "9d1aae2c506f490e54f2a3f4d2f112e5f200709b030103070e61b854e32c00"},            // NOLINT
        {"000000000052a034", "ab6cdb8b305f56d25e6b9a4ba50889a816e51cd20301030706a3af7eaaf000"},            // NOLINT
        {"000000000052a035", "ac72aeaced951f4da6695dee73c2f1b49e03594903010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a036", "b344147ea92cf102cd92ec996b8986ddca4a918e0302c7c90903e4a823bc8f319c29"},      // NOLINT
        {"000000000052a037", "be22ac13ad6af062843eb33adfccfee6bbb4481b0701010203e80101"},                  // NOLINT
        {"000000000052a038", "be996442926a46e76b67eb7279f29adb3a7d6a2f03010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a039", "c19875766825120516450c3754b8ab84fa6e7541"},                                  // NOLINT
        {"000000000052a03a", "c76d89d7322fcfe90e7c192a7bef5d3cf221202603010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a03b", "d0b96c8ab7cedad79185999efbfb20ebdc92bf0d03010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a03c", "d2df9c09b885f69fcf4c12caa03a443d33a21b8803010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a03d", "d65fa0e9e05ee6015e1f7839068c467f57d58fac03010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a03e", "e7a92c9bbace40d323db6abcb3b6900bdea0a18403010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a03f", "e9d5dd241732f2577a1b91d9b297ced3ed232a94030103070e61b854e32c00"},            // NOLINT
        {"000000000052a040", "ed2b73e5a912ac2010dbf0d35515d4873cd9e66903010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a041", "f74a5ca65e4552cff0f13b116113ccb493c580c50501010101"},                        // NOLINT
        {"000000000052a042", "fa08751e2097c5ba14052082ce2bf52a58c8a5be0301030706a3af7eaaf000"},            // NOLINT
        {"000000000052a043", "fb3b466500abc6b9c89192a81501aec6c677eee40301040802c4453ffed3c361"},          // NOLINT
        {"000000000052a044", "fc7a377f85ec306da55f32eccbb7cff2389f569f03010307057ffbb8f2ec00"},            // NOLINT
        {"000000000052a045", "07aaec0b237ccf56b03a7c43c1c7a783da5606420501010101"},                        // NOLINT
        {"000000000052a046", "23b790f50dacb056c5e1ef6bc33fde744a7396330301030708f9d23ce72f8f"},            // NOLINT
        {"000000000052a047", "30d9ed9054681c56bf3cff638b4f3109ed06339a0501010101"},                        // NOLINT
        {"000000000052a048", "3dfbfdf2fdb29d1976d70483eff7552de991be5c030104080dde1159de0970d2"},          // NOLINT
        {"000000000052a049", "4ba4880d287d504e503bc5883848cbcce839e49502072386f26fc10000"},                // NOLINT
        {"000000000052a04a", "56768b032fc12d2e911ef654b0054e26a58cef740301160806e4c6072f54f501"},          // NOLINT
        {"000000000052a04b", "784798960e52dde47705f1aa1c21243ea8222dda030102080ddf6b01cd538869"},          // NOLINT
        {"000000000052a04c", "79a4d418f7887dd4d5123a41b6c8c186686ae8cb030207e90815c70c0d7282e3e0"},        // NOLINT
        {"000000000052a04d", "861ca2f5ff2e03f90d2c3eafda88752fbffc6a69"},                                  // NOLINT
        {"000000000052a04e", "89a284bd0f69a20778f9beba68a9b480957d73050501010101"},                        // NOLINT
        {"000000000052a04f", "8bb2dc06b366a48fbf98824e2d30387b1d8c74880301050706fada176b1c9b"},            // NOLINT
        {"000000000052a050", "b1b19eff752019cd5108dbef2ff56eb1dd0bb06303010407084370e7c6643e"},            // NOLINT
        {"000000000052a051", "c92047cec2355293a9e3710e32851f3509e7313e0501010101"},                        // NOLINT
        {"000000000052a052", "ca3cd40edc45d29b28442e87892a32b020076d590301060804259a347f1cabe0"},          // NOLINT
        {"000000000052a053", "cb9ec8584681f4ffc23029eb5d303370e2112b64030102080ddfa73eec9d9f3e"},          // NOLINT
        {"000000000052a054", "d978cc9c7a93935fecd66c96e2df5f363dc63bc80301050802c345884516e8c6"},          // NOLINT
        {"000000000052a055", "d9a5179f091d85051d3c982785efd1455cec8699030202ae0a432ce76049de515e14e4"},    // NOLINT
        {"000000000052a056", "f14cd6286564e44223ad6aee242623bf4398f99d0301040707e16569c968d2"},            // NOLINT
        {"000000000052a057", "f3a3956d084e3f2a24add02c35c8afd09e3e9bf5030105080c9eea7771667e25"},          // NOLINT
        {"000000000052a058", "053eafe07f12033715d31e1599bbf27dd1c05fb2030105080ddd58b6af8be86e"}           // NOLINT
    };
    db::test_util::MockTransaction transaction;

    auto& tx = transaction;
    SECTION("end == start") {
        EXPECT_CALL(transaction, first_txn_num_in_block(0x52a010))
            .WillOnce(InvokeWithoutArgs([]() -> Task<TxnId> {
                co_return 0;
            }));
        EXPECT_CALL(transaction, first_txn_num_in_block(0x52a011))
            .WillOnce(InvokeWithoutArgs([]() -> Task<TxnId> {
                co_return 20;
            }));
        db::kv::api::HistoryRangeRequest request{
            .table = std::string{db::table::kAccountDomain},
            .from_timestamp = static_cast<db::kv::api::Timestamp>(0),
            .to_timestamp = static_cast<db::kv::api::Timestamp>(19),
            .ascending_order = true};
        EXPECT_CALL(transaction, history_range(std::move(request))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::KeyValueStreamReply> {
            PaginatorKV paginator = [](auto next_page_token) -> Task<PageResultKV> {
                co_return PageResultKV{
                    .keys = {*from_hex("07aaec0b237ccf56b03a7c43c1c7a783da5606420501010101")},
                    .values = {Bytes{}},  // encoded account value doesn't care
                    .next_page_token = std::move(next_page_token)};
            };
            db::kv::api::PaginatedKeysValues result{paginator};
            co_return db::kv::api::KeyValueStreamReply{result};
        }));

        auto result = boost::asio::co_spawn(pool, get_modified_accounts(tx, 0x52a010, 0x52a010, 0x800000), boost::asio::use_future);
        const auto accounts = result.get();
        nlohmann::json j = accounts;
        CHECK(j == R"([
            "0x07aaec0b237ccf56b03a7c43c1c7a783da560642"
        ])"_json);
    }
#ifdef notdef
    SECTION("end == start + 1") {
        auto result = boost::asio::co_spawn(pool, get_modified_accounts(*tx, 0x52a010, 0x52a011), boost::asio::use_future);
        auto accounts = result.get();
        std::cout << "size2: " << accounts.size() << "\n";

        CHECK(accounts.size() == 2);

        nlohmann::json j = accounts;
        CHECK(j == R"([
            "0x07aaec0b237ccf56b03a7c43c1c7a783da560642",
            "0x0c7b6617b9bc0d20f4030ee079d355246246ef70"
        ])"_json);
    }

    SECTION("end >> start") {
        auto result = boost::asio::co_spawn(pool, get_modified_accounts(*tx, 0x52a010, 0x52a058), boost::asio::use_future);
        auto accounts = result.get();

        CHECK(accounts.size() == 70);

        nlohmann::json j = accounts;
        CHECK(j == R"([
            "0x053eafe07f12033715d31e1599bbf27dd1c05fb2",
            "0x07aaec0b237ccf56b03a7c43c1c7a783da560642",
            "0x0c7b6617b9bc0d20f4030ee079d355246246ef70",
            "0x15b1281f4e58215b2c3243d864bdf8b9dddc0da2",
            "0x1a99fb83141a5129a79ed062f6b643b0d4f4770e",
            "0x1b6bf510562cc62b28d23267ab1477dc936405bc",
            "0x209d9af3b5c8fa05d0663db92863ebff7a2f1fff",
            "0x22ea9f6b28db76a7162054c05ed812deb2f519cd",
            "0x23b790f50dacb056c5e1ef6bc33fde744a739633",
            "0x29f030109f19ff6ee9da1257c96620e50725617c",
            "0x2d734d0528bc9fb2722eb639dd3ecd1ece09b69e",
            "0x300e056ec74f9c1189a5cbb22ba46db848d8934c",
            "0x30d9ed9054681c56bf3cff638b4f3109ed06339a",
            "0x311f29bf022343f621278cb3cc8137f8f14ead09",
            "0x329254a40454288f4425220aa6c4173097025e93",
            "0x3432169802ba50d1a2bdbb012cfc449bc4f92c81",
            "0x3546ff99566fadff510fa0befa5b6279e6bc54b9",
            "0x3dfbfdf2fdb29d1976d70483eff7552de991be5c",
            "0x43966453636059ae8b30678b0475550fa53d9eba",
            "0x44bb73af73388f6c21f2ce8acda594172897d125",
            "0x4a3a65a271c40fb77ecfd032e0e15a12f975af7b",
            "0x4ba4880d287d504e503bc5883848cbcce839e495",
            "0x4f980a3ef05eaf6eb2395d8a48594b08502b9033",
            "0x4faa6c7f9ef1c3b575a4075ed4504108a7020ed0",
            "0x50d1443617147cf86f88296780574b40075139a5",
            "0x56768b032fc12d2e911ef654b0054e26a58cef74",
            "0x5c3f649ffdbc91a247ac45fc2c4c63f9319e5135",
            "0x5c954304085df2c17b9931b32129c42f894133dc",
            "0x6eec6a64fb1202e0d3fb3b3e6a3793f13df5cf61",
            "0x71b4daebdab8779a98343981a9a574366f45ee6b",
            "0x784798960e52dde47705f1aa1c21243ea8222dda",
            "0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb",
            "0x7ae250731360126a6f427a55c464134c3d2a9806",
            "0x80a79aac8921189f330db4f2e11f9653dde41ce2",
            "0x8348b5cd154ad11142353bf456a64bd15fe83a86",
            "0x861ca2f5ff2e03f90d2c3eafda88752fbffc6a69",
            "0x88231b2c9e726682d0282602fe33c38388cd89b2",
            "0x884173ac82bad835f297d54a2a71a369efe699b9",
            "0x89a284bd0f69a20778f9beba68a9b480957d7305",
            "0x8a555368749434957ea005ce23a61d41277bd8ab",
            "0x8bb2dc06b366a48fbf98824e2d30387b1d8c7488",
            "0x8dde3d034d5b77ab3102f2626310f63821226a1c",
            "0x901e370c28193fa207f2a6a515c18756db9557f7",
            "0x9a46a5638e41398310908b9194c89dd68582e12d",
            "0x9d1aae2c506f490e54f2a3f4d2f112e5f200709b",
            "0xab6cdb8b305f56d25e6b9a4ba50889a816e51cd2",
            "0xac72aeaced951f4da6695dee73c2f1b49e035949",
            "0xb1b19eff752019cd5108dbef2ff56eb1dd0bb063",
            "0xb344147ea92cf102cd92ec996b8986ddca4a918e",
            "0xbe22ac13ad6af062843eb33adfccfee6bbb4481b",
            "0xbe996442926a46e76b67eb7279f29adb3a7d6a2f",
            "0xc19875766825120516450c3754b8ab84fa6e7541",
            "0xc76d89d7322fcfe90e7c192a7bef5d3cf2212026",
            "0xc92047cec2355293a9e3710e32851f3509e7313e",
            "0xca3cd40edc45d29b28442e87892a32b020076d59",
            "0xcb9ec8584681f4ffc23029eb5d303370e2112b64",
            "0xd0b96c8ab7cedad79185999efbfb20ebdc92bf0d",
            "0xd2df9c09b885f69fcf4c12caa03a443d33a21b88",
            "0xd65fa0e9e05ee6015e1f7839068c467f57d58fac",
            "0xd978cc9c7a93935fecd66c96e2df5f363dc63bc8",
            "0xd9a5179f091d85051d3c982785efd1455cec8699",
            "0xe7a92c9bbace40d323db6abcb3b6900bdea0a184",
            "0xe9d5dd241732f2577a1b91d9b297ced3ed232a94",
            "0xed2b73e5a912ac2010dbf0d35515d4873cd9e669",
            "0xf14cd6286564e44223ad6aee242623bf4398f99d",
            "0xf3a3956d084e3f2a24add02c35c8afd09e3e9bf5",
            "0xf74a5ca65e4552cff0f13b116113ccb493c580c5",
            "0xfa08751e2097c5ba14052082ce2bf52a58c8a5be",
            "0xfb3b466500abc6b9c89192a81501aec6c677eee4",
            "0xfc7a377f85ec306da55f32eccbb7cff2389f569f"
        ])"_json);
    }

    SECTION("start > end") {
        auto result = boost::asio::co_spawn(pool, get_modified_accounts(*tx, 0x52a011, 0x52a010), boost::asio::use_future);
        auto accounts = result.get();

        CHECK(accounts.empty());
    }

    SECTION("start > last block") {
        auto result = boost::asio::co_spawn(pool, get_modified_accounts(*tx, 0x52a061, 0x52a061), boost::asio::use_future);
        CHECK_THROWS_AS(result.get(), std::invalid_argument);
    }
#endif
}
#endif  // !defined(__clang__) && !defined(_WIN32)

#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
