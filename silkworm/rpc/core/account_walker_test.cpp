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

#include "account_walker.hpp"

#include <memory>
#include <string>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/encode.hpp>
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

static const nlohmann::json empty;
static const std::string zeros = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";  // NOLINT

class DummyCursor : public CursorDupSort {
  public:
    explicit DummyCursor(const nlohmann::json& json) : json_{json} {}

    [[nodiscard]] uint32_t cursor_id() const override {
        return 0;
    }

    Task<void> open_cursor(const std::string& table_name, bool /*is_dup_sorted*/) override {
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

        if (++itr_ != table_.end()) {
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

    // NOLINTNEXTLINE(*-rvalue-reference-param-not-moved)
    Task<db::kv::api::DomainPointResult> domain_get(db::kv::api::DomainPointQuery&& /*query*/) override {
        co_return db::kv::api::DomainPointResult{};
    }

    // NOLINTNEXTLINE(*-rvalue-reference-param-not-moved)
    Task<db::kv::api::HistoryPointResult> history_seek(db::kv::api::HistoryPointQuery&& /*query*/) override {
        co_return db::kv::api::HistoryPointResult{};
    }

    // NOLINTNEXTLINE(*-rvalue-reference-param-not-moved)
    Task<db::kv::api::PaginatedTimestamps> index_range(db::kv::api::IndexRangeQuery&& /*query*/) override {
        co_return test::empty_paginated_timestamps();
    }

    // NOLINTNEXTLINE(*-rvalue-reference-param-not-moved)
    Task<db::kv::api::PaginatedKeysValues> history_range(db::kv::api::HistoryRangeQuery&& /*query*/) override {
        co_return test::empty_paginated_keys_and_values();
    }

    // NOLINTNEXTLINE(*-rvalue-reference-param-not-moved)
    Task<db::kv::api::PaginatedKeysValues> domain_range(db::kv::api::DomainRangeQuery&& /*query*/) override {
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

TEST_CASE("AccountWalker::walk_of_accounts") {
    WorkerPool pool{1};
    nlohmann::json json;

    json["PlainState"] = {
        {"79a4d492a05cfd836ea0967edb5943161dd041f7", "0d0101010120d6ea9698de278dad2f31566cd744dd75c4e09925b4bb8f041d265012a940797c"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea", "0d0101010120925fa7384049febb1eddca32821f1f1d709687628c1cf77ef40ca5013d04bdef"},
        {"79a4d75bd00b1843ec5292217e71dace5e5a7439", "03010107181855facbc200"}};
    json["AccountHistory"] = {
        {"79a4d418f7887dd4d5123a41b6c8c186686ae8cb00000000005151a3", "0100000000000000000000003a3000000700000048005f00490025014a0094004b0004004c000f004e0002005100750140000000000100004c0300007604000080040000a0040000a604000082ce04d20dd2ffd20cd312d342d349d34ed359d35fd365d38ad3c7d3cfd3fed309d411d438d441d483d4ece7eee715e819e829e830e839e870e876e877e87fe88ee89ae89be8a2e8aae8afe8b0e8b2e8b6e8b8e8bfe8c0e8c8e8cce8d3e8d9e8dbe8dfe8e9e8efe8f5e8fae800e901e907e909e922e927e92ae92fe936e93ee942e96ae99ee9a9e9c5e9efe97dfe90feabfeb1fed2fe09ff0dff0fff29ff2dff3fff49ff70ff76ff82ff83ff89ff8aff97ff98ff9effa0ffa2ffc0ffc1ffeaff8a23b642c742c842bb6fbd6fd36fdb6f01700470147017701c701e702370327033703a704670477053705d705e70657066706d706e7078708070817088708970917097709870a270a370ab70ad70b370b470bb70c370c470cd70ce70d570e170eb70ec70f97003710471137115711e711f712871337134713c71447146714c7153715471607161716a71727173717c71847186718f7190719971a071a171af71b371c071c771c871d471d571e571e771f171f871f971017209720a720f721172197223722a72317239723a72457246724e7256726072677268726f7270727b728172827289728a72917298729972a272a585ad85af85b185b885b985bd85c685d285d685df85e085e785ef85f085fa85fb850386048610861d861e862886308631863e86408646864786508667866886708671867d8686868786928694869c869d86a586a686ae86af86b886b986c086c186cb86d186eb86f5863887608761877d87a987d19bdc9bdd9bdf9be19be29be39be59be69be79be89bea9beb9bec9bee9b0a9c0c9c0e9c0f9c109c119c129c159c169c179c189c199c1a9c1b9c1c9c1d9c1e9c1f9c219c229c239c249c269c289c299c2a9c2b9c2d9c2e9c2f9c319c329cdbb2dcb2deb2dfb2e0b2e1b2e3b2e4b2e7b2e8b2e9b2eab2edb2efb2f0b2f2b2f3b2f5b2f6b2f7b2f8b2f9b2fab2fbb2fcb2feb2ffb201b302b303b304b307b309b30cb30eb310b311b312b313b314b315b316b317b319b31ab31bb31cb31db31fb320b321b322b324b326b328b329b32bb32eb330b332b333b334b335b336b338b33ab33bb33db33fb37d0587058b058f059205950597059a059e05a105a505a805ab05ae05b105b205b405b605b805bb05bc05bf05c005ab07ae07b007b107b507b807ba07bb07bd07bf07c107c307c407c707c807ca07cc07ce07d007d107d307d407d607d807d907db07dc07de07e507e607e707ea07ec07ee07f007f107f207f607f707f807fa07fd07fe07ff070008020804080608f57c177e1e7e207e227e237e247e267e277e297e2c7e2e7e337e347e357e377e397e3a7e3b7e3d7e3e7e407e417e427e457e467e477e4a7e4c7e4d7e4e7e507e517e527e547e557e567e587e597e5b7e5c7e637e647e657e6b7e6e7e737e747e787e797e7d7e7e7e7f7e877e0b8e2c8e2d8ea98fab8fb08fbc8fc18fc28fc88fc98fcd8fd88fda8fdb8fdd8fde8fdf8fe78fe88f0e901a908d908e90acc16ec571c5cdc501ea8b018d01a001a101bb01bc01c501c701da011302140216022102746476647764aa95ab95b1954a234c234f235023572359235c235e236223642367236a236c237123762377237a237c237f238023832388238c238e238f2392239323972398239b239d239e239f23a323a723ac23ae23b023b223b523b623b923bd23c023c223c423c623c723cd23d023d123d423d623d723d923da23dd23e023e223e423e823eb23ed23ef23f123f423f823fa23fb23fd23fe23012403240424062407240a240b24c024c124c724c824ca24d424d724da24dd24e024e224e824e924eb24ed24ef24f024f124f424f9241b251d251f252225232528252a252f2530253325352538253a253e25412542254525462548254b25502553255425572559255c255d256025622563256525672569256a256c256f257b257d25812584258b258d25163b1a3b1c3b1f3b203b2a3b2c3b2e3b2f3b323b353b383b3a3b3c3b3e3b3f3b403b433b443b453b463b493b4b3b4d3b4e3b593b5b3b8c3b8d3b913b923b933b943b953b983b9a3b9b3b9d3b9e3b9f3ba13ba33ba43ba53ba63ba73ba83baa3bab3bac3bad3bae3baf3bb03bb13bb63bb83bb93bba3bbb3bbc3bbd3bbe3bbf3b063c073c083c093c0a3c0b3c0c3c0d3c0f3c103c113c123c133c143c163c173c183c193c1a3c1b3c1c3c1e3c1f3c203c213c223c233c263c283c293c2b3c2c3c2d3c2f3c303c313c323c333c353c363c373c383c3a3c3c3c3d3c3e3c3f3c403c413c433c7d3c7e3c7f3c803c823c833c843c853c863c883c893c8b3c8c3c8d3c8e3c903c913c923c933c943c953c973c983c993c9a3c9d3c9e3c9f3ca03ca33ca43ca63ca83ca93caa3cad3cae3caf3cb13cb23cb43cb53cb63cb83cb93cba3cbb3cbc3cbd3c094f0b4f0c4f0d4f0f4f104f124f144f164f174f184f194f1b4f1d4f1e4f1f4f204f214f224f244f254f264f274f284f2a4f2b4f2c4f2d4f2f4f304f324f334f344f364f3a4f3b4f3c4f3d4f3f4f414f424f434f444f454f464f82518451855186518751885189518e518f51905192519351945195519751985199519a519b519c519d519f51a051a151a251a351"},  // NOLINT
        {"79a4d418f7887dd4d5123a41b6c8c186686ae8cb000000000052a0b3", "0100000000000000000000003b3001000151000201520032005a00a551040072ba0000efba0600f7ba0100faba0000fcba030004bb030009bb070012bb000014bb010017bb02001bbb00001dbb050024bb000026bb02002abb040030bb00009cbb01009fbb0200a4bb0100a7bb0200abbb0000aebb0200b3bb0100b6bb0100bcbb0000c4bb000025bd000027bd01002cbd00002ebd000030bd0e0040bd000042bd00004fbd030054bd010057bd04005fbd020064bd0200cebd0000d0bd0200d4bd0300d9bd0000dbbd0100e0bd0000e2bd0000e4bd0500ebbd0700f4bd0000f6bd0500fdbd0000ffbd050006be000008be01000bbe040051eb030056eb010059eb030065eb00006deb000077eb090084eb000086eb000088eb00008deb00008feb010092eb020096eb000098eb0a00a4eb0700adeb02000fee000045ee010048ee01004bee00004dee010050ee020054ee000056ee05005dee00005fee000062ee000064ee000066ee000068ee02006eee010071ee010074ee020078ee00007aee07000d9c139c169c179c1b9c219c229c249c279c2c9c2d9c329c349c379c389c3c9c3d9c489c4d9c519c549ca59cb69cb19eb39eb69eda9edc9edd9ee09ee39ee49ee79ee99eed9eee9e969f989fd89f06a007a058a059a05aa05ba05ca05da07ea080a0b2a0b3a0"},                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            // NOLINT
        {"79a4d418f7887dd4d5123a41b6c8c186686ae8cb000000000052a140", "0100000000000000000000003a300000010000005200040010000000b4a03da13ea13fa140a1"},                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  // NOLINT
        {"79a4d418f7887dd4d5123a41b6c8c186686ae8cbffffffffffffffff", "0100000000000000000000003a30000001000000520007001000000041a16fa179a17aa187a195a197a1a5a1"},                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      // NOLINT
        {"79a4d492a05cfd836ea0967edb5943161dd041f7ffffffffffffffff", "0100000000000000000000003a300000010000004b00000010000000019b"},                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981eaffffffffffffffff", "0100000000000000000000003a30000002000000480000004b000100180000001a000000b9e0d505c5c5"},                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          // NOLINT
        {"79a4d75bd00b1843ec5292217e71dace5e5a7439ffffffffffffffff", "0100000000000000000000003a300000020000004500000046000000180000001a0000005b7f3fb1"}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               // NOLINT
    };
    json["AccountChangeSet"] = {
        {"000000000052a0b479a4d418f7887dd4d5123a41b6c8c186686ae8cb", "79a4d418f7887dd4d5123a41b6c8c186686ae8cb030207ea08157fe18268af2da8"}};

    auto database = DummyDatabase{json};
    auto result = boost::asio::co_spawn(pool, database.begin(), boost::asio::use_future);
    auto tx = result.get();
    AccountWalker walker{*tx};

    const BlockNum block_number{0x52a0b3};
    const evmc::address start_address{0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address};

    uint64_t max_result = 1;
    std::vector<KeyValue> collected_data;
    AccountWalker::Collector collector = [&](const silkworm::ByteView k, const silkworm::ByteView v) {
        if (collected_data.size() >= max_result) {
            return false;
        }

        if (k.size() > silkworm::kAddressLength) {
            return true;
        }

        KeyValue kv;
        kv.key = k;
        kv.value = v;
        collected_data.push_back(kv);
        return true;
    };

    SECTION("collect 1 account") {
        max_result = 1;

        auto result1 = boost::asio::co_spawn(pool, walker.walk_of_accounts(block_number, start_address, collector), boost::asio::use_future);
        result1.get();

        CHECK(collected_data.size() == max_result);
        auto& kv = collected_data[0];
        CHECK(silkworm::to_hex(kv.key) == "79a4d492a05cfd836ea0967edb5943161dd041f7");
        CHECK(silkworm::to_hex(kv.value) == "0d0101010120d6ea9698de278dad2f31566cd744dd75c4e09925b4bb8f041d265012a940797c");
    }

    SECTION("collect 2 account") {
        max_result = 2;

        auto result2 = boost::asio::co_spawn(pool, walker.walk_of_accounts(block_number, start_address, collector), boost::asio::use_future);
        result2.get();

        CHECK(collected_data.size() == max_result);
        auto& kv = collected_data[0];
        CHECK(silkworm::to_hex(kv.key) == "79a4d492a05cfd836ea0967edb5943161dd041f7");
        CHECK(silkworm::to_hex(kv.value) == "0d0101010120d6ea9698de278dad2f31566cd744dd75c4e09925b4bb8f041d265012a940797c");

        kv = collected_data[1];
        CHECK(silkworm::to_hex(kv.key) == "79a4d706e4bc7fd8ff9d0593a1311386a7a981ea");
        CHECK(silkworm::to_hex(kv.value) == "0d0101010120925fa7384049febb1eddca32821f1f1d709687628c1cf77ef40ca5013d04bdef");
    }

    SECTION("collect 3 account") {
        max_result = 3;

        auto result3 = boost::asio::co_spawn(pool, walker.walk_of_accounts(block_number, start_address, collector), boost::asio::use_future);
        result3.get();

        CHECK(collected_data.size() == max_result);
        auto& kv = collected_data[0];
        CHECK(silkworm::to_hex(kv.key) == "79a4d492a05cfd836ea0967edb5943161dd041f7");
        CHECK(silkworm::to_hex(kv.value) == "0d0101010120d6ea9698de278dad2f31566cd744dd75c4e09925b4bb8f041d265012a940797c");

        kv = collected_data[1];
        CHECK(silkworm::to_hex(kv.key) == "79a4d706e4bc7fd8ff9d0593a1311386a7a981ea");
        CHECK(silkworm::to_hex(kv.value) == "0d0101010120925fa7384049febb1eddca32821f1f1d709687628c1cf77ef40ca5013d04bdef");

        kv = collected_data[2];
        CHECK(silkworm::to_hex(kv.key) == "79a4d75bd00b1843ec5292217e71dace5e5a7439");
        CHECK(silkworm::to_hex(kv.value) == "03010107181855facbc200");
    }
}

}  // namespace silkworm::rpc
