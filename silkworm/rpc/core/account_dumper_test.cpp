// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "account_dumper.hpp"

#include <memory>
#include <string>

#include <boost/asio/co_spawn.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/db/kv/api/base_transaction.hpp>
#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/db/kv/api/service.hpp>
#include <silkworm/rpc/test_util/dummy_transaction.hpp>

namespace silkworm::rpc {

using db::chain::ChainStorage;
using db::kv::api::BaseTransaction;
using db::kv::api::Cursor;
using db::kv::api::CursorDupSort;
using db::kv::api::KeyValue;

static const nlohmann::json kEmpty;
static const std::string kZeros = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
#ifdef TEST_DISABLED
static const evmc::bytes32 kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;
#endif

class DummyCursor : public CursorDupSort {
  public:
    explicit DummyCursor(const nlohmann::json& json) : json_{json} {}

    uint32_t cursor_id() const override {
        return 0;
    }

    Task<void> open_cursor(const std::string& table_name, bool /*is_dup_sorted*/) override {
        table_name_ = table_name;
        table_ = json_.value(table_name_, kEmpty);
        itr_ = table_.end();

        co_return;
    }

    Task<void> close_cursor() override {
        table_name_ = "";
        co_return;
    }

    Task<KeyValue> seek(silkworm::ByteView key) override {
        const auto key_hex = silkworm::to_hex(key);

        KeyValue out;
        for (itr_ = table_.begin(); itr_ != table_.end(); ++itr_) {
            auto actual = key_hex;
            auto delta = itr_.key().size() - actual.size();
            if (delta > 0) {
                actual += kZeros.substr(0, delta);
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
        const nlohmann::json table = json_.value(table_name_, kEmpty);
        const auto& entry = table.value(silkworm::to_hex(key), "");
        auto value{*silkworm::from_hex(entry)};

        auto kv = KeyValue{silkworm::Bytes{key}, value};

        co_return kv;
    }

    Task<KeyValue> first() override {
        throw std::logic_error{"not implemented"};
    }

    Task<KeyValue> last() override {
        throw std::logic_error{"not implemented"};
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
        silkworm::Bytes key_val{key};
        key_val += value;

        const nlohmann::json table = json_.value(table_name_, kEmpty);
        const auto& entry = table.value(silkworm::to_hex(key_val), "");
        auto out{*silkworm::from_hex(entry)};

        co_return out;
    }

    Task<KeyValue> seek_both_exact(silkworm::ByteView key, silkworm::ByteView value) override {
        silkworm::Bytes key_val{key};
        key_val += value;

        const nlohmann::json table = json_.value(table_name_, kEmpty);
        const auto& entry = table.value(silkworm::to_hex(key_val), "");
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
    DummyTransaction(const nlohmann::json& json) : BaseTransaction{nullptr}, json_{json} {}

    uint64_t tx_id() const override { return 0; }
    uint64_t view_id() const override { return 0; }

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

    std::shared_ptr<ChainStorage> make_storage() override {
        return nullptr;
    }

    Task<TxnId> first_txn_num_in_block(BlockNum /*block_num*/) override {
        co_return 0;
    }

    Task<void> close() override {
        co_return;
    }

    Task<db::kv::api::GetLatestResult> get_latest(db::kv::api::GetLatestRequest /*query*/) override {
        co_return db::kv::api::GetLatestResult{};
    }

    Task<db::kv::api::GetAsOfResult> get_as_of(db::kv::api::GetAsOfRequest /*query*/) override {
        co_return db::kv::api::GetAsOfResult{};
    }

    Task<db::kv::api::HistoryPointResult> history_seek(db::kv::api::HistoryPointRequest /*query*/) override {
        co_return db::kv::api::HistoryPointResult{};
    }

    Task<db::kv::api::PaginatedTimestamps> index_range(db::kv::api::IndexRangeRequest /*query*/) override {
        co_return test::empty_paginated_timestamps();
    }

    Task<db::kv::api::PaginatedKeysValues> history_range(db::kv::api::HistoryRangeRequest /*query*/) override {
        co_return test::empty_paginated_keys_and_values();
    }

    Task<db::kv::api::PaginatedKeysValues> range_as_of(db::kv::api::DomainRangeRequest /*query*/) override {
        co_return test::empty_paginated_keys_and_values();
    }

  private:
    const nlohmann::json& json_;
};

class DummyDatabase : public db::kv::api::Service {
  public:
    explicit DummyDatabase(const nlohmann::json& json) : json_{json} {}

    Task<std::unique_ptr<db::kv::api::Transaction>> begin_transaction() override {
        auto txn = std::make_unique<DummyTransaction>(json_);
        co_return txn;
    }

    Task<db::kv::api::Version> version() override { co_return db::kv::api::kCurrentVersion; }
    Task<void> state_changes(const db::kv::api::StateChangeOptions&, db::kv::api::StateChangeConsumer) override {
        co_return;
    }

  private:
    const nlohmann::json& json_;
};

// const evmc::address start_address{0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address};

#ifdef TEST_DISABLED
TEST_CASE("account dumper") {
    WorkerPool pool{1};
    nlohmann::json json;
    BlockCache block_cache(100, true);

    json["TxSender"] = {
        {"000000000052a0b3e64899e6fe64ebb72b8f65565e9dd765776da064aff9af4601c1efa445dbb0a1", "56768b032fc12d2e911ef654b0054e26a58cef7479a4d418f7887dd4d5123a41b6c8c186686ae8cbf14cd6286564e44223ad6aee242623bf4398f99d8bb2dc06b366a48fbf98824e2d30387b1d8c748823b790f50dacb056c5e1ef6bc33fde744a739633b1b19eff752019cd5108dbef2ff56eb1dd0bb0633dfbfdf2fdb29d1976d70483eff7552de991be5c4ba4880d287d504e503bc5883848cbcce839e495cb9ec8584681f4ffc23029eb5d303370e2112b64f3a3956d084e3f2a24add02c35c8afd09e3e9bf5ca3cd40edc45d29b28442e87892a32b020076d59d978cc9c7a93935fecd66c96e2df5f363dc63bc8784798960e52dde47705f1aa1c21243ea8222dda"},  // NOLINT
    };
    json["CanonicalHeader"] = {
        {"000000000052a0b3", "e64899e6fe64ebb72b8f65565e9dd765776da064aff9af4601c1efa445dbb0a1"}};
    json["Header"] = {
        {"000000000052a0b3e64899e6fe64ebb72b8f65565e9dd765776da064aff9af4601c1efa445dbb0a1", "f9025ea05dfbfea4e8281a3c88251302b934250b4c106ca9e28886996bec4be6d83b5a7ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a09aae6b27d42db5f0130981f83cb17a781cc3450926a1c5f3448776ab303a6062a0070f786d033c1bc1ff1aa0d0bd6284b509c7f996aeae1e2cbf0444d125150d0da055d831ce3b18b3658554040bf6478c4d6f56b973f4228d27d6142b9b3b59adcab901000000140000000000000000000000000000000000080000000000400000000000000000004000000000000000040000000000000400040000000000000020400000000000020000000100000d000000000000000000000000000000008080050040000001020000000408000000000800000000000000000000000010000200000000000000000000020000000000000000000040000000000000000000000000260000000008000800000000000000000000000000000000000000000002000000000002000080000000000000000000000000002000000000000020000020000010000000000010000000000000000020000000000000000000000800000000028352a0b38401c951118312445c84612de46cb861f09f928e20407072796c616273206e6f64652d3020f09f928e0000000000000002e9e802dfe510235dc79ed41e4f712ad17f9e0f0076484cba36993318d7c6b0538e97593097597bc95e6f1a2144eeeeea14982b13667dcbaec7e1b490ed9cd801a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007"}  // NOLINT
    };
    json["BlockBody"] = {{"000000000052a0b3e64899e6fe64ebb72b8f65565e9dd765776da064aff9af4601c1efa445dbb0a1", "c784024402390dc0"}};
    json["BlockTransaction"] = {
        {"0000000002440239", "b89202f88f05168459682f008459682f0a830147f794c92047cec2355293a9e3710e32851f3509e7313e80a4a694fc3a00000000000000000000000000000000000000000000010f0cf064dd59200000c080a0f9f7c30262e7f988fef887dcaa8e210232b5b70a24dacab590f55ad7b4d29813a0369e1621cea46508cdeb8e6ccc3664e7470485662688787c4ee3e3577dbf0651"},                                                // NOLINT
        {"000000000244023a", "b87602f873058207e98459682f008459682f0a82520894861ca2f5ff2e03f90d2c3eafda88752fbffc6a6987470de4df82000080c001a0b6809d941f0c51652eaeefeaabe769ecf20e2ecbc2e2a0f8ffb79674a7dd323ea05a0c7018dba31912dd177d78a11b917be460faad27ca937e66b663abc8e131b9"},                                                                                                        // NOLINT
        {"000000000244023b", "f8a8048459682f0582855c9407aaec0b237ccf56b03a7c43c1c7a783da56064280b844783d80e1000000000000000000000000f14cd6286564e44223ad6aee242623bf4398f99d000000000000000000000000f14cd6286564e44223ad6aee242623bf4398f99d2da02fecfc9a8c280276d7b166c628793e922044a2f89e3e9bb1681774e26b63465ea0419f1f0a7c59d7893ab8e8b4ac15df3ac397144bdce91126c6d0e6578bcceadb"},    // NOLINT
        {"000000000244023c", "f8a9058459682f05830117ef9407aaec0b237ccf56b03a7c43c1c7a783da56064280b844783d80e10000000000000000000000008bb2dc06b366a48fbf98824e2d30387b1d8c74880000000000000000000000008bb2dc06b366a48fbf98824e2d30387b1d8c74882da07fe6c6759140cf4c533f36f4b8a99150d2378a75bd2394d6ddd7e6308c3997c8a003d28b50442328c6ae90d4a830013461244582aeeff13fa56547c27192aaf36c"},  // NOLINT
        {"000000000244023d", "f868038459682f058301f5769407aaec0b237ccf56b03a7c43c1c7a783da56064280845feeed8d2ea0697f347e55c058a03c01026f0f2e485d9255562baf4688db668c1b2cbc96ea45a045fd699769adce06b3b6d829b6ba7bca20e001d01a9a029926648a639d876a16"},                                                                                                                                    // NOLINT
        {"000000000244023e", "f8a9048459682f05830117ef9407aaec0b237ccf56b03a7c43c1c7a783da56064280b844783d80e1000000000000000000000000b1b19eff752019cd5108dbef2ff56eb1dd0bb063000000000000000000000000b1b19eff752019cd5108dbef2ff56eb1dd0bb0632da0ea6937ca91455ac8fc576b5af80dbbd7cff4272008ec50d597384b0830eb4610a07b6df980c9960632bb6da7cb25d101db6b46f4ccabb4931f52c4bbf5d9fc21d3"},  // NOLINT
        {"000000000244023f", "f868048459682f058301f5769407aaec0b237ccf56b03a7c43c1c7a783da56064280845feeed8d2ea0de498c970a1a49b51339172182fbbf23ab6966962e949b54d358ce542f16ff29a002f777a82a4120b8172bf7845aa2f7d2db21b23c757982c8dcd0b52ef7dad2c8"},                                                                                                                                    // NOLINT
        {"0000000002440240", "f868808459682f0583011fab9430d9ed9054681c56bf3cff638b4f3109ed06339a8084d02042a32da0937cf92d2f3e7234d4346947e380aa13e17937e896aa9e799faba0fc0913e765a063952418db203637e0264a6c2be25719d3e3169f5908a594d1ed59cdedc992f0"},                                                                                                                                    // NOLINT
        {"0000000002440241", "f868028459682f0583021cea9407aaec0b237ccf56b03a7c43c1c7a783da56064280845feeed8d2da02df3d3b21eb23af8470e700d028b9b2ab180f1ea5d437dbc858689f3c6d765c1a023aad70dc08bf61f9423b6057e74ae8f496755cce789e5c26ed3c914ec3f2aba"},                                                                                                                                    // NOLINT
        {"0000000002440242", "f868058459682f058301f5769407aaec0b237ccf56b03a7c43c1c7a783da56064280845feeed8d2ea0b5bf525d617be11f12287e0e25f26d9d0abce312d09e4978ea74e77f5e79bf6ca0699d151e6379df76965f9498813259e8a83e7ac09a977bd1c97619d9d4340696"},                                                                                                                                    // NOLINT
        {"0000000002440243", "f868068459682f058301f5769407aaec0b237ccf56b03a7c43c1c7a783da56064280845feeed8d2da0530bb04a9cbfd4bd513b8d7cc127495de9f0303e3aa20c63cae98b2add03859ba060d7b7d6a92a8c4427ca55ce1c819c5f3f9ab57669c04e13d4db379c0600360d"},                                                                                                                                    // NOLINT
        {"0000000002440244", "f868058459682f058301f5769407aaec0b237ccf56b03a7c43c1c7a783da56064280845feeed8d2ea0fc4d95d267881283c62ced98179c96ac36e818b96f6ff1300c30e825825af270a0436e031da786da986afa7d1a01108ad3030d1b760764a8b0d600485f8cba7f0b"},                                                                                                                                    // NOLINT
        {"0000000002440245", "f868028459682f05830129d19407aaec0b237ccf56b03a7c43c1c7a783da5606428084d02042a32ea0fc8d0b3cea1caab2ef34549fb4c0437ab8d7d4034eb5d3d1cd7ae609715f7660a020ec8b1b775c3d1c455f66dd59daac590cadd54d5ff5883ecf7db86fdbf0f6a7"}                                                                                                                                     // NOLINT
    };
    json["PlainState"] = {
        {"79a4d418f7887dd4d5123a41b6c8c186686ae8cb", "030207fc08107ee3bbb7bf3a70"},
        {"79a4d492a05cfd836ea0967edb5943161dd041f7", "0d0101010120d6ea9698de278dad2f31566cd744dd75c4e09925b4bb8f041d265012a940797c"},
        {"79a4d492a05cfd836ea0967edb5943161dd041f700000000000000010000000000000000000000000000000000000000000000000000000000000001", "2ac3c1d3e24b45c6c310534bc2dd84b5ed576335"},  // NOLINT
        {"79a4d492a05cfd836ea0967edb5943161dd041f700000000000000010000000000000000000000000000000000000000000000000000000000000006", "335a9b3f79dcfefda3295be6f7c7c47f077dbcd9"},  // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea", "0d0101010120925fa7384049febb1eddca32821f1f1d709687628c1cf77ef40ca5013d04bdef"},
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea00000000000000010000000000000000000000000000000000000000000000000000000000000001", "2ac3c1d3e24b45c6c310534bc2dd84b5ed576335"},  // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea00000000000000010000000000000000000000000000000000000000000000000000000000000003", "1f6ea08600"},                                // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea00000000000000010000000000000000000000000000000000000000000000000000000000000006", "9d5a08e7551951a3ca73cd84a6409ef1e77f5abe"},  // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea00000000000000010178b166a1bcfd299a6ce6918f016c8d0c52788988d89f65f5727c2fa97be6e9", "1e80355e00"},                                // NOLINT
        {"79a4d706e4bc7fd8ff9d0593a1311386a7a981ea0000000000000001b797965b738ad51ddbf643b315d0421c26972862ca2e64304783dc8930a2b6e8", "ee6b2800"},                                  // NOLINT
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
        {"000000000052a0b479a4d418f7887dd4d5123a41b6c8c186686ae8cb", "79a4d418f7887dd4d5123a41b6c8c186686ae8cb030207ea08157fe18268af2da8"}  // NOLINT
    };
    json["Code"] = {
        {"d6ea9698de278dad2f31566cd744dd75c4e09925b4bb8f041d265012a940797c", "363d3d373d3d3d363d73a8607bb8554de1589893d21d08832ccadbba53ff5af43d82803e903d91602b57fd5bf3"},                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   // NOLINT
        {"925fa7384049febb1eddca32821f1f1d709687628c1cf77ef40ca5013d04bdef", "608060405234801561001057600080fd5b50600436106101425760003560e01c8063b6343b0d116100b8578063b7ec1a331161007c578063b7ec1a33146104e2578063c49f91d3146104ea578063c76a4d31146104f2578063d4c9a8e814610518578063e0bcf13a146105d1578063fc0c546a146105d957610142565b8063b6343b0d1461043e578063b648b4171461048a578063b69ef8a8146104a6578063b7770350146104ae578063b7998907146104da57610142565b80631d1438481161010a5780631d1438481461037d5780632e1a7d4d146103a1578063338f3fed146103be578063488b017c146103ea57806381f03fcb146103f2578063946f46a21461041857610142565b80630d5f26591461014757806312101021146102025780631357e1dc1461021c57806315c3343f146102245780631633fb1d1461022c575b600080fd5b6102006004803603606081101561015d57600080fd5b6001600160a01b0382351691602081013591810190606081016040820135600160201b81111561018c57600080fd5b82018360208201111561019e57600080fd5b803590602001918460018302840111600160201b831117156101bf57600080fd5b91908080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152509295506105e1945050505050565b005b61020a6105f4565b60408051918252519081900360200190f35b61020a6105fa565b61020a610600565b610200600480360360c081101561024257600080fd5b6001600160a01b03823581169260208101359091169160408201359190810190608081016060820135600160201b81111561027c57600080fd5b82018360208201111561028e57600080fd5b803590602001918460018302840111600160201b831117156102af57600080fd5b91908080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092958435959094909350604081019250602001359050600160201b81111561030957600080fd5b82018360208201111561031b57600080fd5b803590602001918460018302840111600160201b8311171561033c57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250929550610624945050505050565b61038561069e565b604080516001600160a01b039092168252519081900360200190f35b610200600480360360208110156103b757600080fd5b50356106ad565b610200600480360360408110156103d457600080fd5b506001600160a01b03813516906020013561080e565b61020a61093a565b61020a6004803603602081101561040857600080fd5b50356001600160a01b031661095e565b6102006004803603602081101561042e57600080fd5b50356001600160a01b0316610970565b6104646004803603602081101561045457600080fd5b50356001600160a01b0316610a4b565b604080519485526020850193909352838301919091526060830152519081900360800190f35b610492610a72565b604080519115158252519081900360200190f35b61020a610a82565b610200600480360360408110156104c457600080fd5b506001600160a01b038135169060200135610afe565b61020a610c20565b61020a610c44565b61020a610c5f565b61020a6004803603602081101561050857600080fd5b50356001600160a01b0316610c83565b6102006004803603606081101561052e57600080fd5b6001600160a01b0382351691602081013591810190606081016040820135600160201b81111561055d57600080fd5b82018360208201111561056f57600080fd5b803590602001918460018302840111600160201b8311171561059057600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250929550610cb4945050505050565b61020a610dc7565b610385610dcd565b6105ef338484600085610ddc565b505050565b60005481565b60035481565b7f48ebe6deff4a5ee645c01506a026031e2a945d6f41f1f4e5098ad65347492c1281565b61063a61063430338789876111cb565b84611243565b6001600160a01b0316866001600160a01b0316146106895760405162461bcd60e51b81526004018080602001828103825260298152602001806118656029913960400191505060405180910390fd5b6106968686868585610ddc565b505050505050565b6006546001600160a01b031681565b6006546001600160a01b03163314610705576040805162461bcd60e51b815260206004820152601660248201527529b4b6b83632a9bbb0b81d103737ba1034b9b9bab2b960511b604482015290519081900360640190fd5b61070d610c44565b81111561074b5760405162461bcd60e51b81526004018080602001828103825260288152602001806118d96028913960400191505060405180910390fd5b6001546006546040805163a9059cbb60e01b81526001600160a01b039283166004820152602481018590529051919092169163a9059cbb9160448083019260209291908290030181600087803b1580156107a457600080fd5b505af11580156107b8573d6000803e3d6000fd5b505050506040513d60208110156107ce57600080fd5b505161080b5760405162461bcd60e51b815260040180806020018281038252602781526020018061183e6027913960400191505060405180910390fd5b50565b6006546001600160a01b03163314610866576040805162461bcd60e51b815260206004820152601660248201527529b4b6b83632a9bbb0b81d103737ba1034b9b9bab2b960511b604482015290519081900360640190fd5b61086e610a82565b60055461087b90836112a5565b11156108b85760405162461bcd60e51b81526004018080602001828103825260348152602001806117a16034913960400191505060405180910390fd5b6001600160a01b038216600090815260046020526040902080546108dc90836112a5565b81556005546108eb90836112a5565b60055560006003820155805460408051918252516001600160a01b038516917f2506c43272ded05d095b91dbba876e66e46888157d3e078db5691496e96c5fad919081900360200190a2505050565b7f7d824962dd0f01520922ea1766c987b1db570cd5db90bdba5ccf5e320607950281565b60026020526000908152604090205481565b6001600160a01b03811660009081526004602052604090206003810154421080159061099f5750600381015415155b6109da5760405162461bcd60e51b81526004018080602001828103825260258152602001806118196025913960400191505060405180910390fd5b600181015481546109ea91611306565b8155600060038201556001810154600554610a0491611306565b600555805460408051918252516001600160a01b038416917f2506c43272ded05d095b91dbba876e66e46888157d3e078db5691496e96c5fad919081900360200190a25050565b60046020526000908152604090208054600182015460028301546003909301549192909184565b600654600160a01b900460ff1681565b600154604080516370a0823160e01b815230600482015290516000926001600160a01b0316916370a08231916024808301926020929190829003018186803b158015610acd57600080fd5b505afa158015610ae1573d6000803e3d6000fd5b505050506040513d6020811015610af757600080fd5b5051905090565b6006546001600160a01b03163314610b56576040805162461bcd60e51b815260206004820152601660248201527529b4b6b83632a9bbb0b81d103737ba1034b9b9bab2b960511b604482015290519081900360640190fd5b6001600160a01b03821660009081526004602052604090208054821115610bae5760405162461bcd60e51b815260040180806020018281038252602781526020018061188e6027913960400191505060405180910390fd5b60008160020154600014610bc6578160020154610bca565b6000545b4281016003840155600183018490556040805185815290519192506001600160a01b038616917fc8305077b495025ec4c1d977b176a762c350bb18cad4666ce1ee85c32b78698a9181900360200190a250505050565b7fe95f353750f192082df064ca5142d3a2d6f0bef0f3ffad66d80d8af86b7a749a81565b6000610c5a600554610c54610a82565b90611306565b905090565b7fc2f8787176b8ac6bf7215b4adcc1e069bf4ab82d9ab1df05a57a91d425935b6e81565b6001600160a01b038116600090815260046020526040812054610cae90610ca8610c44565b906112a5565b92915050565b6006546001600160a01b03163314610d0c576040805162461bcd60e51b815260206004820152601660248201527529b4b6b83632a9bbb0b81d103737ba1034b9b9bab2b960511b604482015290519081900360640190fd5b610d20610d1a308585611348565b82611243565b6001600160a01b0316836001600160a01b031614610d6f5760405162461bcd60e51b81526004018080602001828103825260298152602001806118656029913960400191505060405180910390fd5b6001600160a01b038316600081815260046020908152604091829020600201859055815185815291517f7b816003a769eb718bd9c66bdbd2dd5827da3f92bc6645276876bd7957b08cf09281900390910190a2505050565b60055481565b6001546001600160a01b031681565b6006546001600160a01b03163314610e4857610dfc610d1a3087866113b1565b6006546001600160a01b03908116911614610e485760405162461bcd60e51b81526004018080602001828103825260248152602001806118b56024913960400191505060405180910390fd5b6001600160a01b038516600090815260026020526040812054610e6c908590611306565b90506000610e8282610e7d89610c83565b61141a565b6001600160a01b03881660009081526004602052604081205491925090610eaa90839061141a565b905084821015610f01576040805162461bcd60e51b815260206004820152601d60248201527f53696d706c65537761703a2063616e6e6f74207061792063616c6c6572000000604482015290519081900360640190fd5b8015610f54576001600160a01b038816600090815260046020526040902054610f2a9082611306565b6001600160a01b038916600090815260046020526040902055600554610f509082611306565b6005555b6001600160a01b038816600090815260026020526040902054610f7790836112a5565b6001600160a01b038916600090815260026020526040902055600354610f9d90836112a5565b6003556001546001600160a01b031663a9059cbb88610fbc8589611306565b6040518363ffffffff1660e01b815260040180836001600160a01b0316815260200182815260200192505050602060405180830381600087803b15801561100257600080fd5b505af1158015611016573d6000803e3d6000fd5b505050506040513d602081101561102c57600080fd5b50516110695760405162461bcd60e51b815260040180806020018281038252602781526020018061183e6027913960400191505060405180910390fd5b841561112a576001546040805163a9059cbb60e01b81523360048201526024810188905290516001600160a01b039092169163a9059cbb916044808201926020929091908290030181600087803b1580156110c357600080fd5b505af11580156110d7573d6000803e3d6000fd5b505050506040513d60208110156110ed57600080fd5b505161112a5760405162461bcd60e51b815260040180806020018281038252602781526020018061183e6027913960400191505060405180910390fd5b6040805183815260208101889052808201879052905133916001600160a01b038a811692908c16917f950494fc3642fae5221b6c32e0e45765c95ebb382a04a71b160db0843e74c99f919081900360600190a48183146111c1576006805460ff60a01b1916600160a01b1790556040517f3f4449c047e11092ec54dc0751b6b4817a9162745de856c893a26e611d18ffc490600090a15b5050505050505050565b604080517f7d824962dd0f01520922ea1766c987b1db570cd5db90bdba5ccf5e32060795026020808301919091526001600160a01b0397881682840152958716606082015260808101949094529190941660a083015260c0808301949094528051808303909401845260e09091019052815191012090565b600080611256611251611430565b61148a565b84604051602001808061190160f01b8152506002018381526020018281526020019250505060405160208183030381529060405280519060200120905061129d81846114fd565b949350505050565b6000828201838110156112ff576040805162461bcd60e51b815260206004820152601b60248201527f536166654d6174683a206164646974696f6e206f766572666c6f770000000000604482015290519081900360640190fd5b9392505050565b60006112ff83836040518060400160405280601e81526020017f536166654d6174683a207375627472616374696f6e206f766572666c6f7700008152506116e8565b604080517fe95f353750f192082df064ca5142d3a2d6f0bef0f3ffad66d80d8af86b7a749a6020808301919091526001600160a01b03958616828401529390941660608501526080808501929092528051808503909201825260a0909301909252815191012090565b604080517f48ebe6deff4a5ee645c01506a026031e2a945d6f41f1f4e5098ad65347492c126020808301919091526001600160a01b03958616828401529390941660608501526080808501929092528051808503909201825260a0909301909252815191012090565b600081831061142957816112ff565b5090919050565b61143861177f565b506040805160a081018252600a6060820190815269436865717565626f6f6b60b01b608083015281528151808301835260038152620312e360ec1b602082810191909152820152469181019190915290565b805180516020918201208183015180519083012060409384015184517fc2f8787176b8ac6bf7215b4adcc1e069bf4ab82d9ab1df05a57a91d425935b6e818601528086019390935260608301919091526080808301919091528351808303909101815260a0909101909252815191012090565b60008151604114611555576040805162461bcd60e51b815260206004820152601f60248201527f45434453413a20696e76616c6964207369676e6174757265206c656e67746800604482015290519081900360640190fd5b60208201516040830151606084015160001a7f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a08211156115c65760405162461bcd60e51b81526004018080602001828103825260228152602001806117d56022913960400191505060405180910390fd5b8060ff16601b141580156115de57508060ff16601c14155b1561161a5760405162461bcd60e51b81526004018080602001828103825260228152602001806117f76022913960400191505060405180910390fd5b600060018783868660405160008152602001604052604051808581526020018460ff1681526020018381526020018281526020019450505050506020604051602081039080840390855afa158015611676573d6000803e3d6000fd5b5050604051601f1901519150506001600160a01b0381166116de576040805162461bcd60e51b815260206004820152601860248201527f45434453413a20696e76616c6964207369676e61747572650000000000000000604482015290519081900360640190fd5b9695505050505050565b600081848411156117775760405162461bcd60e51b81526004018080602001828103825283818151815260200191508051906020019080838360005b8381101561173c578181015183820152602001611724565b50505050905090810190601f1680156117695780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b505050900390565b6040518060600160405280606081526020016060815260200160008152509056fe53696d706c65537761703a2068617264206465706f7369742063616e6e6f74206265206d6f7265207468616e2062616c616e636545434453413a20696e76616c6964207369676e6174757265202773272076616c756545434453413a20696e76616c6964207369676e6174757265202776272076616c756553696d706c65537761703a206465706f736974206e6f74207965742074696d6564206f757453696d706c65537761703a2053696d706c65537761703a207472616e73666572206661696c656453696d706c65537761703a20696e76616c69642062656e6566696369617279207369676e617475726553696d706c65537761703a2068617264206465706f736974206e6f742073756666696369656e7453696d706c65537761703a20696e76616c696420697373756572207369676e617475726553696d706c65537761703a206c697175696442616c616e6365206e6f742073756666696369656e74a2646970667358221220e966e3935e65edd1eee5f40a145487964af1fa6f0f5e354d400ee94b6a207d1364736f6c634300060c0033"}  // NOLINT
    };
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
    auto begin_result = boost::asio::co_spawn(pool, database.begin(), boost::asio::use_future);
    auto tx = begin_result.get();
    core::AccountDumper ad{*tx};

    const BlockNumOrHash block_num_or_hash{0x52a0b3};
    const evmc::address start_address{0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address};

    const evmc::bytes32 root{0x9aae6b27d42db5f0130981f83cb17a781cc3450926a1c5f3448776ab303a6062_bytes32};

    evmc::address address_1 = 0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address;
    evmc::address address_2 = 0x79a4d492a05cfd836ea0967edb5943161dd041f7_address;
    evmc::address address_3 = 0x79a4d706e4bc7fd8ff9d0593a1311386a7a981ea_address;

    evmc::bytes32 root_1 = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;
    // evmc::bytes32 root_2 = 0xd0e669fbe330badbad9746ffbe0eded2c37d0044b71984204ec3d42b7ed405f5_bytes32;
    // evmc::bytes32 root_3 = 0xf88d7fd6659bcd2fdd4c62038f86cdea902d401c5d4d682288027310e5cca24e_bytes32;

    evmc::bytes32 code_hash_1 = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32;
    evmc::bytes32 code_hash_2 = 0xd6ea9698de278dad2f31566cd744dd75c4e09925b4bb8f041d265012a940797c_bytes32;
    evmc::bytes32 code_hash_3 = 0x925fa7384049febb1eddca32821f1f1d709687628c1cf77ef40ca5013d04bdef_bytes32;

    SECTION("1 result, exclude code and storage") {
        int16_t max_result = 1;
        bool exclude_code = true;
        bool exclude_storage = true;
        auto result = boost::asio::co_spawn(pool, ad.dump_accounts(block_cache, block_num_or_hash, start_address, max_result, exclude_code, exclude_storage), boost::asio::use_future);
        const DumpAccounts& da = result.get();

        CHECK(da.root == root);
        CHECK(da.accounts.size() == static_cast<size_t>(max_result));

        CHECK(da.accounts.find(address_1) != da.accounts.end());

        const auto& account = da.accounts.at(address_1);
        CHECK(account.balance == 1549204747057049000);
        CHECK(account.nonce == 2026);
        CHECK(account.incarnation == 0);
        CHECK(account.root == kZeroHash);
        CHECK(account.code_hash == code_hash_1);
        CHECK(!account.code.has_value());
        CHECK(!account.storage.has_value());
    }

    SECTION("2 result, exclude code and storage") {
        int16_t max_result = 2;
        bool exclude_code = true;
        bool exclude_storage = true;
        auto result = boost::asio::co_spawn(pool, ad.dump_accounts(block_cache, block_num_or_hash, start_address, max_result, exclude_code, exclude_storage), boost::asio::use_future);
        const DumpAccounts& da = result.get();

        CHECK(da.root == root);
        CHECK(da.accounts.size() == static_cast<size_t>(max_result));

        CHECK(da.accounts.find(address_1) != da.accounts.end());
        auto account = da.accounts.at(address_1);
        CHECK(account.balance == 1549204747057049000);
        CHECK(account.nonce == 2026);
        CHECK(account.incarnation == 0);
        CHECK(account.root == kZeroHash);
        CHECK(account.code_hash == code_hash_1);
        CHECK(!account.code.has_value());
        CHECK(!account.storage.has_value());

        CHECK(da.accounts.find(address_2) != da.accounts.end());
        account = da.accounts.at(address_2);
        CHECK(account.balance == 0);
        CHECK(account.nonce == 1);
        CHECK(account.incarnation == 1);
        CHECK(account.root == kZeroHash);
        CHECK(account.code_hash == code_hash_2);
        CHECK(!account.code.has_value());
        CHECK(!account.storage.has_value());
    }

    SECTION("3 result, exclude code and storage") {
        int16_t max_result = 3;
        bool exclude_code = true;
        bool exclude_storage = true;
        auto result = boost::asio::co_spawn(pool, ad.dump_accounts(block_cache, block_num_or_hash, start_address, max_result, exclude_code, exclude_storage), boost::asio::use_future);
        const DumpAccounts& da = result.get();

        CHECK(da.root == root);
        CHECK(da.accounts.size() == static_cast<size_t>(max_result));

        CHECK(da.accounts.find(address_1) != da.accounts.end());
        auto account = da.accounts.at(address_1);
        CHECK(account.balance == 1549204747057049000);
        CHECK(account.nonce == 2026);
        CHECK(account.incarnation == 0);
        CHECK(account.root == kZeroHash);
        CHECK(account.code_hash == code_hash_1);
        CHECK(!account.code.has_value());
        CHECK(!account.storage.has_value());

        CHECK(da.accounts.find(address_2) != da.accounts.end());
        account = da.accounts.at(address_2);
        CHECK(account.balance == 0);
        CHECK(account.nonce == 1);
        CHECK(account.incarnation == 1);
        CHECK(account.root == kZeroHash);
        CHECK(account.code_hash == code_hash_2);
        CHECK(!account.code.has_value());
        CHECK(!account.storage.has_value());

        CHECK(da.accounts.find(address_3) != da.accounts.end());
        account = da.accounts.at(address_3);
        CHECK(account.balance == 0);
        CHECK(account.nonce == 1);
        CHECK(account.incarnation == 1);
        CHECK(account.root == kZeroHash);
        CHECK(account.code_hash == code_hash_3);
        CHECK(!account.code.has_value());
        CHECK(!account.storage.has_value());
    }

    SECTION("1 result, include code exclude storage") {
        int16_t max_result = 1;
        bool exclude_code = false;
        bool exclude_storage = true;
        auto result = boost::asio::co_spawn(pool, ad.dump_accounts(block_cache, block_num_or_hash, start_address, max_result, exclude_code, exclude_storage), boost::asio::use_future);
        const DumpAccounts& da = result.get();

        CHECK(da.root == root);
        CHECK(da.accounts.size() == static_cast<size_t>(max_result));

        CHECK(da.accounts.find(address_1) != da.accounts.end());

        const auto& account = da.accounts.at(address_1);
        CHECK(account.balance == 1549204747057049000);
        CHECK(account.nonce == 2026);
        CHECK(account.incarnation == 0);
        CHECK(account.root == kZeroHash);
        CHECK(account.code_hash == code_hash_1);
        CHECK(!account.code.has_value());
        CHECK(!account.storage.has_value());
    }

    SECTION("2 result, include code exclude storage") {
        int16_t max_result = 2;
        bool exclude_code = false;
        bool exclude_storage = true;
        auto result = boost::asio::co_spawn(pool, ad.dump_accounts(block_cache, block_num_or_hash, start_address, max_result, exclude_code, exclude_storage), boost::asio::use_future);
        const DumpAccounts& da = result.get();

        CHECK(da.root == root);
        CHECK(da.accounts.size() == static_cast<size_t>(max_result));

        CHECK(da.accounts.find(address_1) != da.accounts.end());
        auto account = da.accounts.at(address_1);
        CHECK(account.balance == 1549204747057049000);
        CHECK(account.nonce == 2026);
        CHECK(account.incarnation == 0);
        CHECK(account.root == kZeroHash);
        CHECK(account.code_hash == code_hash_1);
        CHECK(!account.code.has_value());
        CHECK(!account.storage.has_value());

        CHECK(da.accounts.find(address_2) != da.accounts.end());
        account = da.accounts.at(address_2);
        CHECK(account.balance == 0);
        CHECK(account.nonce == 1);
        CHECK(account.incarnation == 1);
        CHECK(account.root == kZeroHash);
        CHECK(account.code_hash == code_hash_2);
        CHECK(account.code.has_value());
        CHECK(account.code.value() == *silkworm::from_hex("0x363d3d373d3d3d363d73a8607bb8554de1589893d21d08832ccadbba53ff5af43d82803e903d91602b57fd5bf3"));
        CHECK(!account.storage.has_value());
    }

    SECTION("3 result, include code exclude storage") {
        int16_t max_result = 3;
        bool exclude_code = false;
        bool exclude_storage = true;
        auto result = boost::asio::co_spawn(pool, ad.dump_accounts(block_cache, block_num_or_hash, start_address, max_result, exclude_code, exclude_storage), boost::asio::use_future);
        const DumpAccounts& da = result.get();

        CHECK(da.root == root);
        CHECK(da.accounts.size() == static_cast<size_t>(max_result));

        CHECK(da.accounts.find(address_1) != da.accounts.end());
        auto account = da.accounts.at(address_1);
        CHECK(account.balance == 1549204747057049000);
        CHECK(account.nonce == 2026);
        CHECK(account.incarnation == 0);
        CHECK(account.root == kZeroHash);
        CHECK(account.code_hash == code_hash_1);
        CHECK(!account.code.has_value());
        CHECK(!account.storage.has_value());

        CHECK(da.accounts.find(address_2) != da.accounts.end());
        account = da.accounts.at(address_2);
        CHECK(account.balance == 0);
        CHECK(account.nonce == 1);
        CHECK(account.incarnation == 1);
        CHECK(account.root == kZeroHash);
        CHECK(account.code_hash == code_hash_2);
        CHECK(account.code.has_value());
        CHECK(account.code.value() == *silkworm::from_hex("0x363d3d373d3d3d363d73a8607bb8554de1589893d21d08832ccadbba53ff5af43d82803e903d91602b57fd5bf3"));
        CHECK(!account.storage.has_value());

        CHECK(da.accounts.find(address_3) != da.accounts.end());
        account = da.accounts.at(address_3);
        CHECK(account.balance == 0);
        CHECK(account.nonce == 1);
        CHECK(account.incarnation == 1);
        CHECK(account.root == kZeroHash);
        CHECK(account.code_hash == code_hash_3);
        CHECK(account.code.has_value());
        CHECK(!account.storage.has_value());
    }

    SECTION("1 result, include code and storage") {
        int16_t max_result = 1;
        bool exclude_code = false;
        bool exclude_storage = false;
        auto result = boost::asio::co_spawn(pool, ad.dump_accounts(block_cache, block_num_or_hash, start_address, max_result, exclude_code, exclude_storage), boost::asio::use_future);
        const DumpAccounts& da = result.get();

        CHECK(da.root == root);
        CHECK(da.accounts.size() == static_cast<size_t>(max_result));

        CHECK(da.accounts.find(address_1) != da.accounts.end());

        const auto& account = da.accounts.at(address_1);
        CHECK(account.balance == 1549204747057049000);
        CHECK(account.nonce == 2026);
        CHECK(account.incarnation == 0);
        CHECK(account.root == root_1);
        CHECK(account.code_hash == code_hash_1);
        CHECK(!account.code.has_value());
        CHECK(!account.storage.has_value());
    }

    /*SECTION("2 result, include code and storage") {
        uint64_t max_result = 2;
        bool exclude_code = false;
        bool exclude_storage = false;
        auto result = boost::asio::co_spawn(pool, ad.dump_accounts(block_cache, block_num_or_hash, start_address, max_result, exclude_code, exclude_storage), boost::asio::use_future);
        const DumpAccounts &da = result.get();

        CHECK(da.root == root);
        CHECK(da.accounts.size() == max_result);

        CHECK(da.accounts.find(address_1) != da.accounts.end());
        auto account = da.accounts.at(address_1);
        CHECK(account.balance == 1549204747057049000);
        CHECK(account.nonce == 2026);
        CHECK(account.incarnation == 0);
        CHECK(account.root == root_1);
        CHECK(account.code_hash == code_hash_1);
        CHECK(!account.code.has_value());
        CHECK(!account.storage.has_value());

        CHECK(da.accounts.find(address_2) != da.accounts.end());
        account = da.accounts.at(address_2);
        CHECK(account.balance == 0);
        CHECK(account.nonce == 1);
        CHECK(account.incarnation == 1);
        CHECK(account.root == root_2);
        CHECK(account.code_hash == code_hash_2);
        CHECK(account.code.has_value());
        CHECK(account.code.value() == *silkworm::from_hex("0x363d3d373d3d3d363d73a8607bb8554de1589893d21d08832ccadbba53ff5af43d82803e903d91602b57fd5bf3"));
        CHECK(account.storage.has_value());
        auto storage = account.storage.value();
        CHECK(storage.size() == 2);
        CHECK(storage[0x0000000000000000000000000000000000000000000000000000000000000001_bytes32] == *silkworm::from_hex("2ac3c1d3e24b45c6c310534bc2dd84b5ed576335"));
        CHECK(storage[0x0000000000000000000000000000000000000000000000000000000000000006_bytes32] == *silkworm::from_hex("335a9b3f79dcfefda3295be6f7c7c47f077dbcd9"));
    }

    SECTION("3 result, include code and storage") {
        uint64_t max_result = 3;
        bool exclude_code = false;
        bool exclude_storage = false;
        auto result = boost::asio::co_spawn(pool, ad.dump_accounts(block_cache, block_num_or_hash, start_address, max_result, exclude_code, exclude_storage), boost::asio::use_future);
        const DumpAccounts &da = result.get();

        CHECK(da.root == root);
        CHECK(da.accounts.size() == max_result);

        CHECK(da.accounts.find(address_1) != da.accounts.end());
        auto account = da.accounts.at(address_1);
        CHECK(account.balance == 1549204747057049000);
        CHECK(account.nonce == 2026);
        CHECK(account.incarnation == 0);
        CHECK(account.root == root_1);
        CHECK(account.code_hash == code_hash_1);
        CHECK(!account.code.has_value());
        CHECK(!account.storage.has_value());

        CHECK(da.accounts.find(address_2) != da.accounts.end());
        account = da.accounts.at(address_2);
        CHECK(account.balance == 0);
        CHECK(account.nonce == 1);
        CHECK(account.incarnation == 1);
        CHECK(account.root == root_2);
        CHECK(account.code_hash == code_hash_2);
        CHECK(account.code.has_value());
        CHECK(account.code.value() == *silkworm::from_hex("0x363d3d373d3d3d363d73a8607bb8554de1589893d21d08832ccadbba53ff5af43d82803e903d91602b57fd5bf3"));
        CHECK(account.storage.has_value());
        auto storage = account.storage.value();
        CHECK(storage.size() == 2);
        CHECK(storage[0x0000000000000000000000000000000000000000000000000000000000000001_bytes32] == *silkworm::from_hex("2ac3c1d3e24b45c6c310534bc2dd84b5ed576335"));
        CHECK(storage[0x0000000000000000000000000000000000000000000000000000000000000006_bytes32] == *silkworm::from_hex("335a9b3f79dcfefda3295be6f7c7c47f077dbcd9"));

        CHECK(da.accounts.find(address_3) != da.accounts.end());
        account = da.accounts.at(address_3);
        CHECK(account.balance == 0);
        CHECK(account.nonce == 1);
        CHECK(account.incarnation == 1);
        CHECK(account.root == root_3);
        CHECK(account.code_hash == code_hash_3);
        CHECK(account.code.has_value());
        CHECK(account.storage.has_value());
        storage = account.storage.value();
        CHECK(storage.size() == 5);
        CHECK(storage[0x0000000000000000000000000000000000000000000000000000000000000001_bytes32] == *silkworm::from_hex("2ac3c1d3e24b45c6c310534bc2dd84b5ed576335"));
        CHECK(storage[0x0000000000000000000000000000000000000000000000000000000000000003_bytes32] == *silkworm::from_hex("1f6ea08600"));
        CHECK(storage[0x0000000000000000000000000000000000000000000000000000000000000006_bytes32] == *silkworm::from_hex("9d5a08e7551951a3ca73cd84a6409ef1e77f5abe"));
        CHECK(storage[0x0178b166a1bcfd299a6ce6918f016c8d0c52788988d89f65f5727c2fa97be6e9_bytes32] == *silkworm::from_hex("1e80355e00"));
        CHECK(storage[0xb797965b738ad51ddbf643b315d0421c26972862ca2e64304783dc8930a2b6e8_bytes32] == *silkworm::from_hex("ee6b2800"));
    }*/
}
#endif

}  // namespace silkworm::rpc
