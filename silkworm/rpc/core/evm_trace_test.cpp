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

#include "evm_trace.hpp"

#include <string>
#include <utility>

#include <boost/asio/thread_pool.hpp>
#include <catch2/catch_test_macros.hpp>
#include <evmc/instructions.h>
#include <gmock/gmock.h>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/db/kv/api/endpoint/key_value.hpp>
#include <silkworm/db/state/remote_state.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/test_util/mock_back_end.hpp>
#include <silkworm/rpc/test_util/mock_block_cache.hpp>
#include <silkworm/rpc/test_util/service_context_test_base.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm::rpc::trace {

using db::chain::RemoteChainStorage;
using db::kv::api::KeyValue;
using testing::_;
using testing::Invoke;
using testing::InvokeWithoutArgs;

static const Bytes kZeroKey{*silkworm::from_hex("0000000000000000")};
static const Bytes kZeroHeader{*silkworm::from_hex("bf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a")};

static const Bytes kConfigKey{kZeroHeader};
static const Bytes kConfigValue{string_view_to_byte_view(kSepoliaConfig.to_json().dump())};  // NOLINT(cppcoreguidelines-interfaces-global-init)

struct TraceCallExecutorTest : public test_util::ServiceContextTestBase {
    db::test_util::MockTransaction transaction;
    WorkerPool workers{1};
    test::MockBlockCache block_cache;
    StringWriter writer{4096};
    boost::asio::any_io_executor io_executor{io_context_.get_executor()};
    std::unique_ptr<ethbackend::BackEnd> backend = std::make_unique<test::BackEndMock>();
    RemoteChainStorage chain_storage{transaction, ethdb::kv::make_backend_providers(backend.get())};
};

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_call precompiled") {
    static Bytes kAccountHistoryKey1{*silkworm::from_hex("0a6bb546b9208cfab9e8fa2b9b2c042b18df703000000000009db707")};
    static Bytes kAccountHistoryKey2{*silkworm::from_hex("000000000000000000000000000000000000000900000000009db707")};
    static Bytes kAccountHistoryKey3{*silkworm::from_hex("000000000000000000000000000000000000000000000000009db707")};

    static Bytes kPlainStateKey1{*silkworm::from_hex("0a6bb546b9208cfab9e8fa2b9b2c042b18df7030")};
    static Bytes kPlainStateKey2{*silkworm::from_hex("0000000000000000000000000000000000000009")};
    static Bytes kPlainStateKey3{*silkworm::from_hex("000000000000000000000000000000000000000")};

    auto& tx = transaction;
    EXPECT_CALL(transaction, create_state(_, _, _)).Times(2).WillRepeatedly(Invoke([&tx](auto& ioc, const auto& storage, auto block_number) -> std::shared_ptr<State> {
        return std::make_shared<db::state::RemoteState>(ioc, tx, storage, block_number);
    }));

    SECTION("precompiled contract failure") {
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, Bytes{}};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, Bytes{}};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, Bytes{}};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey3}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));

        evmc::address blake2f_precompile{0x0000000000000000000000000000000000000009_address};

        Call call;
        call.from = 0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address;
        call.to = blake2f_precompile;
        call.gas = 50'000;
        call.gas_price = 7;

        silkworm::Block block{};
        block.header.number = 10'336'006;

        TraceConfig config{true, true, true};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(!result.pre_check_error);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                    "balance":{
                        "+":"0x55730"
                    },
                    "code":{
                        "+":"0x"
                    },
                    "nonce":{
                        "+":"0x0"
                    },
                    "storage":{}
                },
                "0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030":{
                    "balance":{
                        "+":"0x0"
                    },
                    "code":{
                        "+":"0x"
                    },
                    "nonce":{
                        "+":"0x1"
                    },
                    "storage":{}
                }
            },
            "trace":[],
            "vmTrace": {
                "code": "0x",
                "ops": []
            }
        })"_json);
    }
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_call 1") {
    static Bytes kAccountHistoryKey1{*silkworm::from_hex("e0a2bd4258d2768837baa26a28fe71dc079f84c700000000005279a8")};
    static Bytes kAccountHistoryValue1{*silkworm::from_hex(
        "0100000000000000000000003a300000010000005200c003100000008a5e905e9c5ea55ead5eb25eb75ebf5ec95ed25ed75ee15eed5ef25efa"
        "5eff5e085f115f1a5f235f2c5f355f3e5f475f505f595f625f6b5f745f7c5f865f8f5f985fa15faa5faf5fb45fb95fc15fce5fd75fe05fe65f"
        "f25ffb5f04600d6016601f602860306035603a6043604c6055605a606760706079607f608b6094609d60a560af60b860c160ca60d360db60e5"
        "60ee60f460fb600061096111611b6124612d6136613f61486151615a6160616c6175617e6187618f619961a261ab61b461bb61c661cc61d861"
        "e161ea61f361fc6102620e6217622062296230623a6241624d6256625f6271627a6283628c6295629e62a762b062b662c262ca62d462dc62e6"
        "62ef62f86201630a6313631c6325632e63376340634963526358635e6364636a6374637d6388639663a163ac63b563bc63c463ca63d063d963"
        "df63e563eb63f163fd6306640d641264186421642a6433643c6445644c64516457645d64646469647264776484648d6496649f64a864b164c3"
        "64cc64d164de64e764ee64f96402650b6514651d6526652f6538653d6547654d6553655c6565656e657765886592659b65a465ad65b665bf65"
        "c665cb65d165da65e365ec65f565fe6507661066196622662b6634663d6646664f6658666166676672667c6685668e669766a066a966b266bb"
        "66c466ca66d666df66e866f166f766fc6603670c6715671e6724673067386742674b67516757675d6766676f67786781678a678f6796679c67"
        "a167ae67b767c067c967d267e167ed67f667ff67086810681a682368296835683e684768506859685e686b6874687d6886688f689868a168aa"
        "68b368bc68c568ce68e068e968f268fb6804690d6916691f69266931693a6943694c6955695e6967697069796982698b6994699d69a669af69"
        "b869c169ca69d369dc69e569ee69f769fe69086a126a1b6a246a366a3f6a486a516a5a6a636a6c6a7e6a876a906a966aa26aab6ab46abd6ac6"
        "6acf6ad56adb6ae16aea6af36afc6a056b0e6b176b206b296b326b3b6b416b4b6b566b5c6b676b716b7a6b806b886b956b9e6ba76bb06bb96b"
        "bf6bc56bcb6bd06bd56bdd6be66bef6b016c0a6c136c1c6c226c2d6c346c406c496c526c5a6c646c6d6c766c7f6c886c916c966c9c6ca36cac"
        "6cb56cbe6cc76cd06cd96ce26ce86cf16cfd6c066d0f6d186d216d2a6d336d3c6d456d4e6d576d606d696d726d7b6d846d8a6d966d9f6da46d"
        "b16dba6dc36dcc6dd56dde6de76df06df76d026e096e146e1d6e266e2f6e386e416e4a6e516e5c6e656e6c6e746e806e896e906e9b6ea46ead"
        "6eb76ebf6ec86ed16eda6ee36eec6ef56efe6e076f0d6f196f226f2b6f346f3d6f466f4f6f586f616f666f706f776f7c6f856f8e6f976f9e6f"
        "a96fb26fb96fc46fcd6fd66fdc6fe36fe86ff16ffa6fff6f0c7015701e702670397042704b70527058705d7066706f70787081708a7093709a"
        "70a570ae70b770c070c970d170d970e470ed70f670fc7008711271197123712c7135713e714771597162716b7174717a7186718f719871a171"
        "aa71b371bc71c571ce71d771e071f271fb7104720d7216721f72287231723a7240724c7255725b7267726d7279728272897291729d72a672ac"
        "72b872c072ca72d372d972e572ee72f772007309731273197324732d7336733f73487351735a7363736c7375737a73877390739973a273ab73"
        "b473bd73c673cf73d873e173e773ee73f373fc7305740a7419742074297432743b7444744d7456745f746b747174797483748c7495749e74a7"
        "74b074b974c274cb74d074d774dd74e374ee74f87401750a7513751c7525752e7537754975527558755f7564756d7576757f75877591759a75"
        "a375aa75af75b575be75c775d075d975e275eb75f475fd750676187621762a7632763c7645764d7657766076697672767b7683768d7696769f"
        "76a876b176ba76c376cc76d576de76e776f076f97602770b7714771d7724772f77387741774a7753775c7765776e7774778077897792779b77"
        "a477aa77b177b677bf77c577d177da77e377e977f077f577fe7707781078197822782b7834783d7846784f78587861786a7873787c7885788e"
        "789778a078a878b178b878c478cd78d678df78e878f178fa7803790c7915791e7924793079387942794b7954795d7963796e79787981798979"
        "8e7993799879a579ab79b779c079c979d279db79e479ed79f679ff79087a117a1a7a237a2b7a357a3c7a447a507a597a627a6b7a747a7d7a86"
        "7a8f7a987aa17aaa7ab37abc7ac57ace7ad57ae07ae97aee7af87a017b0d7b167b1f7b287b2e7b377b3e7b437b4c7b557b5e7b677b707b797b"
        "827b8b7b947b9a7ba37baf7bb57bbc7bc17bca7bd37bdc7be47bea7bf57b007c097c0f7c197c217c2d7c367c3f7c487c517c5a7c637c6c7c75"
        "7c7e7c877c907c997ca17cab7cb27cb87cbd7cc67ccf7cd67ce17cea7cf37cfc7c057d0b7d177d207d297d317d3b7d417d4d7d537d5f7d657d"
        "6d7d777d837d8c7d957d9e7da77db07db97dc27dcb7dd27dd77ddd7de67def7df87d017e0a7e137e1c7e257e2e7e377e407e497e4f7e557e5b"
        "7e647e6a7e727e7f7e887e917e967ea37eac7eb57ebe7ec77ed07ed67ee27eeb7ef47efd7e037f0f7f187f217f2a7f337f3c7f457f4e7f577f"
        "607f667f727f7b7f847f8d7f")};

    static Bytes kAccountHistoryKey2{*silkworm::from_hex("52728289eba496b6080d57d0250a90663a07e55600000000005279a8")};
    static Bytes kAccountHistoryValue2{*silkworm::from_hex("0100000000000000000000003a300000010000004e00000010000000d63b")};

    static Bytes kAccountHistoryKey3{*silkworm::from_hex("000000000000000000000000000000000000000000000000005279a8")};
    static Bytes kAccountHistoryValue3{*silkworm::from_hex(
        "0100000000000000000000003b30270000000040202b003f002c001c002d0009002e000a002f000000300000003100000032000b003300"
        "0200340011003500030036000a003700040038000800390000003a0000003b0007003c0000003d000a003e0003003f0002004000060041"
        "000200420002004300010044000200450003004700050048000400490039004a0012004b0003004c0012004d00c2004e0010004f000500"
        "50007a0051001700520000005300650049010000c901000003020000170200002d0200002f02000031020000330200004b020000510200"
        "00750200007d020000930200009d020000af020000b1020000b3020000c3020000c5020000db020000e3020000e9020000f7020000fd02"
        "000003030000070300000d03000015030000210300002b0300009f030000c5030000cd030000f3030000790500009b050000a70500009d"
        "060000c3060000c5060000988d9b8d9c8d9d8d9f8da08da18da38da48da58da68da78da88da98dab8dac8dad8dae8daf8db08db18db28d"
        "b38db48db58dba8dbb8dbc8dbd8dbe8dbf8dc18dc28dc38dc48dc58dc68dc88dc98dca8d598fa7a2f6a2f9a207a344a3c8a331a446a423"
        "ad27ad37ae3cae40ae58ee5aee61eeb8eebeee44ef91ef9cef23f189f1c403ec033c047905b605d4120d133b147d147b168616641a5624"
        "c2cec6dce5dcd7df25e02ee071e093e0a2e00ae11de344e387e3a3e3abe37de43b249824413f5741734203549654a554bc5419db204529"
        "4530454c45d4abf0ab05ac0cac13ac18ac00b9dfb63f7fe3535bc76de078e080e088e095e09ce0a7e0aee0b4e0b8e0bde014431a4306a6"
        "d625e025ed25ff252e39ed3916722972497258725f7250735f738e749b74587c9b7c7da001657983a0d5a9d5c91fcd1f1a2046216d4975"
        "4a084bef6cf376418d8f8d113f4b49a1491a4db5e9ec542355a35c816b9a6cc3719e791c8909b4ce45f817bf4c074de94dfb4d154e1a4e"
        "1e4e714fa6b183bd84bd87bd8cbd8fbdc0bdabc0b8c0dbc0ebc011c5740543065c06630666436843754341754975f6a5a7ccf7e71aec2e"
        "fab12676415dfb73f280f287f2040f21369b5818863c86a5b2b4b2bab2afb4277fdf7ff27ff97fbd80cf808da643a80db4dbe3d2ff6511"
        "69116b116d116e1171117311d813f5138f149214c8142615411544156a1575157d157e15a415a515f31777448e44ba4d3155625b685b35"
        "5c425c585c465de15dd26b4f7250726072219328935d935e93a193e493e593e693ee93ef93f893fa931b941c94f3abb4aebeaeb2af6cb5"
        "fccc29cf09004cb4000037be000039be00003bbe09005dd1000060d1000062d100007fea010068eb0000af2b2442a79900d99e367b394d"
        "5fa17448c94dc98bcbe0cdf7cd74ce7dce86ceeecefece12cf30cf36cf3ccf49cf630a9c0a2025b93608500f5023502a502b5035503d50"
        "3e5043504b504d504e5054505650d250d750dd50e450e950f250f750fe5003510d6214621a621f6225622b62336235623a624162426247"
        "624c62556262626b6271627d6282628d6294629a62a162aa62b362b962bf62c462ca62ce62d662d762df62e762ee62f762ff6201630663"
        "0d6316631b632063286331633a6343634963506355635b6361636463706375637e63866387638f6394639a63a063a663ae63b463ba63c1"
        "63c663cb63d163db63e263e963ee63f363f863d78172947b948494899496949d94a494ad94b194b894be94c394cc94d594dd94e294e794"
        "ef94f694fb94029507950d9514951a951f9526952e9538953d9549954f9558955c9561956c95749577958095859592959795a395ad95b4"
        "95ba95bb95c195c895d195d695e395e895ee95f595fb95049610961696229628962e9634963d9646964f96549605975b97bd9714a234a7"
        "50c16fc501d80ad814d82cd841d84bd863d870d87cd84de3c3e989fb93fba7fbc9fefffe54ffdb07fb3f664f9c5099587d8a418b888be4"
        "8e2a90e49d91b59ddfd7e55be61de86ef3f1096579667a0a7def8bbcbb0b0f3b16974265537753895392539b53a453ad53b653d153da53"
        "e853f053f553fe530754105422542b5434543d5446544b54505461546a5473547c5485549754a054bb54c454ce54de54e654f154fa5403"
        "55095515551e55275542555d5578559c55a555aa55b355c055c555db55ed55f655fe550356085611561a5623562c5635563e5662566b56"
        "745686568f569856a156b356bc56c556ce56f256fb5604570a571f57315743574c575e577057795781578b5794579d57a657af57c157dc"
        "57e557f457fc57095819581b5824582d583b584858515862586c5875587e589958a058ab58b458bd58aa5a635dbc5dd65d568bc79a279b"
        "09000f770300147704001e770800287700003ba1000042be0000e2be0000fbbe0000edc500001b369f2b7444cf78de78327938793f7944"
        "794c79517957795c79637968796d79727979797e79837989798e79957996799d79aa79ab79b079b679bd79c279c779cf79d479da79db79"
        "e179e679ec79f379f879017a037a067a0d7a0e7a137a187a1f7a207a287a2d7a327a387a3d7a447a4a7a567a5b7a617a687afc7a017b08"
        "7b0e7b137b197b257b377b437b497b557b5f7b6a7b6c7b6d7b8d7b9f7ba97baf7bb57bbe7bc47bc57bd57bad7db37dbe7dbf7dd17de57d"
        "f17dfb7d017e0b7e157e207e287e2b7e397e4b7e517e5f7e")};

    static Bytes kAccountChangeSetKey{*silkworm::from_hex("00000000005279ab")};
    static Bytes kAccountChangeSetSubkey{*silkworm::from_hex("e0a2bd4258d2768837baa26a28fe71dc079f84c7")};
    static Bytes kAccountChangeSetValue{*silkworm::from_hex("030203430b141e903194951083c424fd")};

    static Bytes kAccountChangeSetKey1{*silkworm::from_hex("0000000000532b9f")};
    static Bytes kAccountChangeSetSubkey1{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes kAccountChangeSetValue1{*silkworm::from_hex("020944ed67f28fd50bb8e9")};

    static Bytes kPlainStateKey1{*silkworm::from_hex("e0a2bd4258d2768837baa26a28fe71dc079f84c7")};
    static Bytes kPlainStateKey2{*silkworm::from_hex("52728289eba496b6080d57d0250a90663a07e556")};

    auto& tx = transaction;
    EXPECT_CALL(transaction, create_state(_, _, _)).Times(2).WillRepeatedly(Invoke([&tx](auto& ioc, const auto& storage, auto block_number) -> std::shared_ptr<State> {
        return std::make_shared<db::state::RemoteState>(ioc, tx, storage, block_number);
    }));

    SECTION("Call: failed with intrinsic gas too low") {
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));

        const auto block_number = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 50'000;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");

        silkworm::Block block{};
        block.header.number = block_number;

        TraceConfig config{false, false, false};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == true);
        CHECK(result.pre_check_error.value() == "intrinsic gas too low: have 50000, want 53072");
    }

    SECTION("Call: full output") {
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey}, silkworm::ByteView{kAccountChangeSetSubkey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue;
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1}, silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue1;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));

        const auto block_number = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 118'936;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");

        silkworm::Block block{};
        block.header.number = block_number;

        TraceConfig config{true, true, true};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                "balance": {
                    "*": {
                    "from": "0x44ed67f28fd50bb8e9",
                    "to": "0x44ed67f28fd513c08f"
                    }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
                },
                "0x52728289eba496b6080d57d0250a90663a07e556": {
                "balance": {
                    "+": "0x0"
                },
                "code": {
                    "+": "0x"
                },
                "nonce": {
                    "+": "0x1"
                },
                "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": {
                    "+": "0x000000000000000000000000000000000000000000000000000000000000002a"
                    }
                }
                },
                "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7": {
                "balance": "=",
                "code": "=",
                "nonce": {
                    "*": {
                    "from": "0x343",
                    "to": "0x344"
                    }
                },
                "storage": {}
                }
            },
            "trace": [
                {
                "action": {
                    "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                    "gas": "0x10148",
                    "init": "0x602a60005500",
                    "value": "0x0"
                },
                "result": {
                    "address": "0x52728289eba496b6080d57d0250a90663a07e556",
                    "code": "0x",
                    "gasUsed": "0x565a"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "create"
                }
            ],
            "vmTrace": {
                "code": "0x602a60005500",
                "ops": [
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x2a"
                    ],
                    "store": null,
                    "used": 65861
                    },
                    "idx": "0",
                    "op": "PUSH1",
                    "pc": 0,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 65858
                    },
                    "idx": "1",
                    "op": "PUSH1",
                    "pc": 2,
                    "sub": null
                },
                {
                    "cost": 22100,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": {
                        "key": "0x0",
                        "val": "0x2a"
                    },
                    "used": 43758
                    },
                    "idx": "2",
                    "op": "SSTORE",
                    "pc": 4,
                    "sub": null
                },
                {
                    "cost": 0,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 43758
                    },
                    "idx": "3",
                    "op": "STOP",
                    "pc": 5,
                    "sub": null
                }
                ]
            }
        })"_json);
    }

    SECTION("Call: no vmTrace") {
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey}, silkworm::ByteView{kAccountChangeSetSubkey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue;
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1}, silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue1;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));

        const auto block_number = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 118'936;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");

        silkworm::Block block{};
        block.header.number = block_number;

        TraceConfig config{false, true, true};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                "balance": {
                    "*": {
                    "from": "0x44ed67f28fd50bb8e9",
                    "to": "0x44ed67f28fd513c08f"
                    }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
                },
                "0x52728289eba496b6080d57d0250a90663a07e556": {
                "balance": {
                    "+": "0x0"
                },
                "code": {
                    "+": "0x"
                },
                "nonce": {
                    "+": "0x1"
                },
                "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": {
                    "+": "0x000000000000000000000000000000000000000000000000000000000000002a"
                    }
                }
                },
                "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7": {
                "balance": "=",
                "code": "=",
                "nonce": {
                    "*": {
                    "from": "0x343",
                    "to": "0x344"
                    }
                },
                "storage": {}
                }
            },
            "trace": [
                {
                "action": {
                    "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                    "gas": "0x10148",
                    "init": "0x602a60005500",
                    "value": "0x0"
                },
                "result": {
                    "address": "0x52728289eba496b6080d57d0250a90663a07e556",
                    "code": "0x",
                    "gasUsed": "0x565a"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "create"
                }
            ],
            "vmTrace": null
        })"_json);
    }

    SECTION("Call: no trace") {
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey}, silkworm::ByteView{kAccountChangeSetSubkey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue;
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1}, silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue1;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));

        const auto block_number = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 118'936;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");

        silkworm::Block block{};
        block.header.number = block_number;

        TraceConfig config{true, false, true};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                "balance": {
                    "*": {
                    "from": "0x44ed67f28fd50bb8e9",
                    "to": "0x44ed67f28fd513c08f"
                    }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
                },
                "0x52728289eba496b6080d57d0250a90663a07e556": {
                "balance": {
                    "+": "0x0"
                },
                "code": {
                    "+": "0x"
                },
                "nonce": {
                    "+": "0x1"
                },
                "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": {
                    "+": "0x000000000000000000000000000000000000000000000000000000000000002a"
                    }
                }
                },
                "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7": {
                "balance": "=",
                "code": "=",
                "nonce": {
                    "*": {
                    "from": "0x343",
                    "to": "0x344"
                    }
                },
                "storage": {}
                }
            },
            "trace": [],
            "vmTrace": {
                "code": "0x602a60005500",
                "ops": [
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x2a"
                    ],
                    "store": null,
                    "used": 65861
                    },
                    "idx": "0",
                    "op": "PUSH1",
                    "pc": 0,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 65858
                    },
                    "idx": "1",
                    "op": "PUSH1",
                    "pc": 2,
                    "sub": null
                },
                {
                    "cost": 22100,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": {
                        "key": "0x0",
                        "val": "0x2a"
                    },
                    "used": 43758
                    },
                    "idx": "2",
                    "op": "SSTORE",
                    "pc": 4,
                    "sub": null
                },
                {
                    "cost": 0,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 43758
                    },
                    "idx": "3",
                    "op": "STOP",
                    "pc": 5,
                    "sub": null
                }
                ]
            }
        })"_json);
    }

    SECTION("Call: no stateDiff") {
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey}, silkworm::ByteView{kAccountChangeSetSubkey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue;
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1}, silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue1;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));

        const auto block_number = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 118'936;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");

        silkworm::Block block{};
        block.header.number = block_number;

        TraceConfig config{true, true, false};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": null,
            "trace": [
                {
                "action": {
                    "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                    "gas": "0x10148",
                    "init": "0x602a60005500",
                    "value": "0x0"
                },
                "result": {
                    "address": "0x52728289eba496b6080d57d0250a90663a07e556",
                    "code": "0x",
                    "gasUsed": "0x565a"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "create"
                }
            ],
            "vmTrace": {
                "code": "0x602a60005500",
                "ops": [
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x2a"
                    ],
                    "store": null,
                    "used": 65861
                    },
                    "idx": "0",
                    "op": "PUSH1",
                    "pc": 0,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 65858
                    },
                    "idx": "1",
                    "op": "PUSH1",
                    "pc": 2,
                    "sub": null
                },
                {
                    "cost": 22100,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": {
                        "key": "0x0",
                        "val": "0x2a"
                    },
                    "used": 43758
                    },
                    "idx": "2",
                    "op": "SSTORE",
                    "pc": 4,
                    "sub": null
                },
                {
                    "cost": 0,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 43758
                    },
                    "idx": "3",
                    "op": "STOP",
                    "pc": 5,
                    "sub": null
                }
                ]
            }
        })"_json);
    }

    SECTION("Call: no vmTrace, trace and stateDiff") {
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey}, silkworm::ByteView{kAccountChangeSetSubkey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue;
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1}, silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue1;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));

        const auto block_number = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 118'936;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");

        silkworm::Block block{};
        block.header.number = block_number;

        TraceConfig config{false, false, false};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": null,
            "trace": [],
            "vmTrace": null
        })"_json);
    }
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_call 2") {
    static Bytes kAccountHistoryKey1{*silkworm::from_hex("8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b900000000004366ad")};
    static Bytes kAccountHistoryValue1{*silkworm::from_hex(
        "0100000000000000000000003a300000010000004300c00310000000d460da60de60f86008610d611161136125612d6149615c61626182"
        "619161bd61bf61cb61cd61d361e761e961f061f461f761f961026208620a620f621162176219621c621e621f622162246228622a622d62"
        "36623762386240624d625262536255625a625c625e62906296629b62a562a962ad62bc62be62c062c262ca62cf62d362dc62e362ea621b"
        "63216327632a63316338633d633f63426344634d634f6355636363656367636d63716373638563876389639b639c639f63a163a263a363"
        "bd63c263c863cb63cd63d663d863de63e163e6632c642f6430643b643e64406441644964526458645e64606464646864716474649464a6"
        "64ab64ac64cb64d164d464d564df64ee64f864fa64fb6409650c650e6510651165136536653c654565516564656f657265786590659465"
        "99659b65aa65af65b865bc65be65c465c665c765ca65cb65cc65cf65d065d265d465d765d965df65e565e865ea65ee65f365f465f965fa"
        "65fc65fe6500660166036605660b660c660f6614661766196620662166226624662566276629662a662d662f663066336638663a663d66"
        "3f66416645664c66516656665a665c665d665f6663666c6672667b66866688668a668d668f66926698669a669c669f66ac66ae66b166bb"
        "66c366c666c866ca66cc66cd66cf66d366db66dd66de66e066e366e566e966ec66ee66f566f666f766f966fb6600670267046706670867"
        "09670b670d6711671367146719671c672f673a6740674367446748674d675e67656769676b676c676e67706777677e6780678e67926795"
        "67a267ab67b467bc67c167db67e067e267e367e567e767ea67f167f66700681768196826682868306833683568376839683b683d683f68"
        "406848684d684f6852685368546857685b685d685e6865686b687068736877687a6880688e6890689b689f68a268b468bb68ca68ce68d0"
        "68db68f16803691069166921692569276929692c6937693c693e69416954695669586960696169646971698169a069bc69be69c069c169"
        "c369c469c569c669c969cb69cc69ce69cf69d169d269d369d669e269e469e769eb69f369f969fb69ff69006a036a046a056a076a0a6a0c"
        "6a0e6a116a216a2b6a386a3b6a406a626a9d6a9f6aa16aa36aa56aa76aa86aaa6aab6aac6aad6aaf6ab26ab36ab56ab66ab86ab96abb6a"
        "bc6abd6abf6ac06ac26ace6ad96ae06af56af66af86afd6a026b0a6b0d6b186b206b216b246b276b2b6b2c6b306b336b346b366b386b3a"
        "6b3c6b3e6b406b436b456b486b496b4a6b4c6b4e6b506b546b576b596b5b6b616b636b646b676b696b6b6b6d6b706b726b786b796b7a6b"
        "976ba86bab6bb06bd16bd76bd86bda6bdc6be16be66bee6bf06bf26b056c086c256c326c346c376c3d6c496c4e6c516c576c626c656c69"
        "6c6e6c7a6c7c6c826c876c8d6c926c956c976c9e6ca06ca26ca46ca96cb86cbf6cc26cdc6ce06ce26ce76cea6cef6cf16c026d236d2f6d"
        "326d346d4a6d686d6b6d716d896d8a6d8c6d8d6d916db56dba6dd26ddf6d2c6e6c6e796e9d6e9f6eb46e406f456f5b6f5c6f5e6f726f80"
        "6f826f836f856f876f9d6fab6fce6fd06ffe6f027007700b7014702f7038704c70667072708270867087708970a270a570a870aa70ac70"
        "b270b570b770b970ba70bc70bf70c270c570c770ca70cd70cf70ff70167117711a711c7123712c7131713d7147714d7153715a71607165"
        "71667168716a717f718971a071a771a971c971cd71cf71d071d171d271d371d471d671d771d871d971db71dc71f871fd71007201720372"
        "05720672087209720c720e721172127213721572177219721c721e722072227227722872297230723472377238723b723d723f72407244"
        "72477249728c728f729b72a072a372a872ac72ae72c272c672c872cb72cd72cf72d472dc72df72057306730a7323732d73327335733b73"
        "40734273447349734a734e735573587359735c735e735f7364736573667369736a736b73747385739373957396739d73a273af73b173b3"
        "73b973c073c873e273e473e773ee73f173f573267429742e743074337434748e749174937496749d749e74a174a474ac74b074b974c074"
        "c774c974cb74cd74d574d674d874d974da74de74e174e574fd74027505751a751d751f75227524752675277529752c7532753375347535"
        "754c7559755c756e757175737581758c759675ad75cb75e575e675f575f775f975007607760c7617764b765c7669766f76717672767476"
        "7576777678769276a776aa76ab76eb76f276067728773a773c774b777177a377b577db77ee77f077f477fb770678177826782c782e7833"
        "783a7841784578477849788178917895789878a478a778aa78ae78b178b478c578d278d378d678d778d878db78ee78f578177926793679"
        "40794d79507995799b79a079a379cf79ee79f4790a7a1b7a297a347a357a587a617a8e7a907a927a977a997a9a7aa07aa17aa67aa87aab"
        "7ac97acd7ad27ad77adb7add7ae47a0d7b377b6d7ba57ba67bb17bbd7bc07bc97bd57bd77bd97bda7bdd7bde7be07beb7bef7bf17bfb7b"
        "ff7b067c0d7c167c1d7c1f7c207c227c247c2c7c2e7c317c3d7c3f7c497c597c627c647c667c817c827c857c8d7c917c997c9b7c9c7c9f"
        "7ca47ca67ca87caa7cac7caf7cb37cc97ce57cf57c077d087d")};

    static Bytes kAccountHistoryKey2{*silkworm::from_hex("5e1f0c9ddbe3cb57b80c933fab5151627d7966fa00000000004366ad")};
    static Bytes kAccountHistoryValue2{*silkworm::from_hex(
        "0100000000000000000000003a300000020000004000020043000c00180000001e0000005e8d618d628d826688668d668f66a466ac"
        "66b866bb66cf66db6623678e67d167")};

    static Bytes kAccountHistoryKey3{*silkworm::from_hex("000000000000000000000000000000000000000000000000004366ad")};
    static Bytes kAccountHistoryValue3{*silkworm::from_hex(
        "0100000000000000000000003b30270000000040202b003f002c001c002d0009002e000a002f000000300000003100000032000b003300"
        "0200340011003500030036000a003700040038000800390000003a0000003b0007003c0000003d000a003e0003003f0002004000060041"
        "000200420002004300010044000200450003004700050048000400490039004a0012004b0003004c0012004d00c2004e0010004f000500"
        "50007a0051001700520000005300650049010000c901000003020000170200002d0200002f02000031020000330200004b020000510200"
        "00750200007d020000930200009d020000af020000b1020000b3020000c3020000c5020000db020000e3020000e9020000f7020000fd02"
        "000003030000070300000d03000015030000210300002b0300009f030000c5030000cd030000f3030000790500009b050000a70500009d"
        "060000c3060000c5060000988d9b8d9c8d9d8d9f8da08da18da38da48da58da68da78da88da98dab8dac8dad8dae8daf8db08db18db28d"
        "b38db48db58dba8dbb8dbc8dbd8dbe8dbf8dc18dc28dc38dc48dc58dc68dc88dc98dca8d598fa7a2f6a2f9a207a344a3c8a331a446a423"
        "ad27ad37ae3cae40ae58ee5aee61eeb8eebeee44ef91ef9cef23f189f1c403ec033c047905b605d4120d133b147d147b168616641a5624"
        "c2cec6dce5dcd7df25e02ee071e093e0a2e00ae11de344e387e3a3e3abe37de43b249824413f5741734203549654a554bc5419db204529"
        "4530454c45d4abf0ab05ac0cac13ac18ac00b9dfb63f7fe3535bc76de078e080e088e095e09ce0a7e0aee0b4e0b8e0bde014431a4306a6"
        "d625e025ed25ff252e39ed3916722972497258725f7250735f738e749b74587c9b7c7da001657983a0d5a9d5c91fcd1f1a2046216d4975"
        "4a084bef6cf376418d8f8d113f4b49a1491a4db5e9ec542355a35c816b9a6cc3719e791c8909b4ce45f817bf4c074de94dfb4d154e1a4e"
        "1e4e714fa6b183bd84bd87bd8cbd8fbdc0bdabc0b8c0dbc0ebc011c5740543065c06630666436843754341754975f6a5a7ccf7e71aec2e"
        "fab12676415dfb73f280f287f2040f21369b5818863c86a5b2b4b2bab2afb4277fdf7ff27ff97fbd80cf808da643a80db4dbe3d2ff6511"
        "69116b116d116e1171117311d813f5138f149214c8142615411544156a1575157d157e15a415a515f31777448e44ba4d3155625b685b35"
        "5c425c585c465de15dd26b4f7250726072219328935d935e93a193e493e593e693ee93ef93f893fa931b941c94f3abb4aebeaeb2af6cb5"
        "fccc29cf09004cb4000037be000039be00003bbe09005dd1000060d1000062d100007fea010068eb0000af2b2442a79900d99e367b394d"
        "5fa17448c94dc98bcbe0cdf7cd74ce7dce86ceeecefece12cf30cf36cf3ccf49cf630a9c0a2025b93608500f5023502a502b5035503d50"
        "3e5043504b504d504e5054505650d250d750dd50e450e950f250f750fe5003510d6214621a621f6225622b62336235623a624162426247"
        "624c62556262626b6271627d6282628d6294629a62a162aa62b362b962bf62c462ca62ce62d662d762df62e762ee62f762ff6201630663"
        "0d6316631b632063286331633a6343634963506355635b6361636463706375637e63866387638f6394639a63a063a663ae63b463ba63c1"
        "63c663cb63d163db63e263e963ee63f363f863d78172947b948494899496949d94a494ad94b194b894be94c394cc94d594dd94e294e794"
        "ef94f694fb94029507950d9514951a951f9526952e9538953d9549954f9558955c9561956c95749577958095859592959795a395ad95b4"
        "95ba95bb95c195c895d195d695e395e895ee95f595fb95049610961696229628962e9634963d9646964f96549605975b97bd9714a234a7"
        "50c16fc501d80ad814d82cd841d84bd863d870d87cd84de3c3e989fb93fba7fbc9fefffe54ffdb07fb3f664f9c5099587d8a418b888be4"
        "8e2a90e49d91b59ddfd7e55be61de86ef3f1096579667a0a7def8bbcbb0b0f3b16974265537753895392539b53a453ad53b653d153da53"
        "e853f053f553fe530754105422542b5434543d5446544b54505461546a5473547c5485549754a054bb54c454ce54de54e654f154fa5403"
        "55095515551e55275542555d5578559c55a555aa55b355c055c555db55ed55f655fe550356085611561a5623562c5635563e5662566b56"
        "745686568f569856a156b356bc56c556ce56f256fb5604570a571f57315743574c575e577057795781578b5794579d57a657af57c157dc"
        "57e557f457fc57095819581b5824582d583b584858515862586c5875587e589958a058ab58b458bd58aa5a635dbc5dd65d568bc79a279b"
        "09000f770300147704001e770800287700003ba1000042be0000e2be0000fbbe0000edc500001b369f2b7444cf78de78327938793f7944"
        "794c79517957795c79637968796d79727979797e79837989798e79957996799d79aa79ab79b079b679bd79c279c779cf79d479da79db79"
        "e179e679ec79f379f879017a037a067a0d7a0e7a137a187a1f7a207a287a2d7a327a387a3d7a447a4a7a567a5b7a617a687afc7a017b08"
        "7b0e7b137b197b257b377b437b497b557b5f7b6a7b6c7b6d7b8d7b9f7ba97baf7bb57bbe7bc47bc57bd57bad7db37dbe7dbf7dd17de57d"
        "f17dfb7d017e0b7e157e207e287e2b7e397e4b7e517e5f7e")};

    static Bytes kAccountChangeSetKey1{*silkworm::from_hex("00000000004366ae")};
    static Bytes kAccountChangeSetSubkey1{*silkworm::from_hex("8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9")};
    static Bytes kAccountChangeSetValue1{*silkworm::from_hex("0303038c330a01a098914888dc0516d2")};

    static Bytes kAccountChangeSetKey2{*silkworm::from_hex("00000000004366b8")};
    static Bytes kAccountChangeSetSubkey2{*silkworm::from_hex("5e1f0c9ddbe3cb57b80c933fab5151627d7966fa")};
    static Bytes kAccountChangeSetValue2{*silkworm::from_hex("03010408014219564ff26a00")};

    static Bytes kPlainStateKey{*silkworm::from_hex("0000000000000000000000000000000000000000")};

    auto& tx = transaction;
    EXPECT_CALL(transaction, create_state(_, _, _)).Times(2).WillRepeatedly(Invoke([&tx](auto& ioc, const auto& storage, auto block_number) -> std::shared_ptr<State> {
        return std::make_shared<db::state::RemoteState>(ioc, tx, storage, block_number);
    }));

    SECTION("Call: TO present") {
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                SILK_DEBUG << "EXPECT_CALL::get "
                           << " table: " << db::table::kCanonicalHashesName
                           << " key: " << silkworm::to_hex(kZeroKey)
                           << " value: " << silkworm::to_hex(kZeroHeader);
                co_return kZeroHeader;
            }));
        EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                SILK_DEBUG << "EXPECT_CALL::get "
                           << " table: " << db::table::kConfigName
                           << " key: " << silkworm::to_hex(kConfigKey)
                           << " value: " << silkworm::to_hex(kConfigValue);
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                SILK_DEBUG << "EXPECT_CALL::get "
                           << " table: " << db::table::kAccountHistoryName
                           << " key: " << silkworm::to_hex(kAccountHistoryKey1)
                           << " value: " << silkworm::to_hex(kAccountHistoryValue1);
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(transaction,
                    get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1},
                                   silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillRepeatedly(InvokeWithoutArgs(
                []() -> Task<std::optional<Bytes>> {
                    SILK_DEBUG << "EXPECT_CALL::get_both_range "
                               << " table: " << db::table::kAccountChangeSetName
                               << " key: " << silkworm::to_hex(kAccountChangeSetKey1)
                               << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey1)
                               << " value: " << silkworm::to_hex(kAccountChangeSetValue1);
                    co_return kAccountChangeSetValue1;
                }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                SILK_DEBUG << "EXPECT_CALL::get "
                           << " table: " << db::table::kAccountHistoryName
                           << " key: " << silkworm::to_hex(kAccountHistoryKey2)
                           << " value: " << silkworm::to_hex(kAccountHistoryValue2);
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                SILK_DEBUG << "EXPECT_CALL::get "
                           << " table: " << db::table::kAccountHistoryName
                           << " key: " << silkworm::to_hex(kAccountHistoryKey3)
                           << " value: " << silkworm::to_hex(kAccountHistoryValue3);
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue3};
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2},
                                                silkworm::ByteView{kAccountChangeSetSubkey2}))
            .WillRepeatedly(InvokeWithoutArgs(
                []() -> Task<std::optional<Bytes>> {
                    SILK_DEBUG << "EXPECT_CALL::get_both_range "
                               << " table: " << db::table::kAccountChangeSetName
                               << " key: " << silkworm::to_hex(kAccountChangeSetKey2)
                               << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey2)
                               << " value: " << silkworm::to_hex(kAccountChangeSetValue2);
                    co_return kAccountChangeSetValue2;
                }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));

        const auto block_number = 4'417'196;  // 0x4366AC
        Call call;
        call.from = 0x8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9_address;
        call.to = 0x5e1f0c9ddbe3cb57b80c933fab5151627d7966fa_address;
        call.value = 50'000'000;
        call.gas = 30'000;
        call.gas_price = 1'000'000'000;
        call.data = *silkworm::from_hex("00");

        silkworm::Block block{};
        block.header.number = block_number;

        TraceConfig config{true, true, true};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};

        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                "balance": {
                    "+": "0x131a5ff57800"
                },
                "code": {
                    "+": "0x"
                },
                "nonce": {
                    "+": "0x0"
                },
                "storage": {}
                },
                "0x5e1f0c9ddbe3cb57b80c933fab5151627d7966fa": {
                "balance": {
                    "*": {
                    "from": "0x14219564ff26a00",
                    "to": "0x142195652ed5a80"
                    }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
                },
                "0x8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9": {
                "balance": {
                    "*": {
                    "from": "0x1a098914888dc0516d2",
                    "to": "0x1a098914888d90a2652"
                    }
                },
                "code": "=",
                "nonce": {
                    "*": {
                    "from": "0x38c33",
                    "to": "0x38c34"
                    }
                },
                "storage": {}
                }
            },
            "trace": [
                {
                "action": {
                    "callType": "call",
                    "from": "0x8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9",
                    "gas": "0x2324",
                    "input": "0x00",
                    "to": "0x5e1f0c9ddbe3cb57b80c933fab5151627d7966fa",
                    "value": "0x2faf080"
                },
                "result": {
                    "gasUsed": "0x0",
                    "output": "0x"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "call"
                }
            ],
            "vmTrace": {
                "code": "0x",
                "ops": []
            }
        })"_json);
    }
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_call with error") {
    static Bytes kAccountHistoryKey1{*silkworm::from_hex("578f0a154b23be77fc2033197fbc775637648ad400000000005279a8")};
    static Bytes kAccountHistoryValue1{*silkworm::from_hex(
        "0100000000000000000000003a300000010000005200650010000000a074f7740275247527752b75307549756d75787581758a75937598"
        "759e75a275a775a975af75b775ce75eb75f67508760f7613769f76a176a376be76ca76ce76d876e576fb76267741776177627769777077"
        "7c7783779e79a279a579a779ad79b279448a458a4d8a568a638acfa0d4a0d6a0d8a0dfa0e2a0e5a0e9a0eca0efa0f1a0f5a0fea003a10a"
        "a117a11ba131a135a139a152a154a158a15aa15da171a175a17ca1b4a1e4a124a21fbb22bb26bb2bbb2dbb2fbb34bb38bb3fbb0bd14ed2"
        "a0e5a3e550eb60eb6ceb72eb")};

    static Bytes kAccountHistoryKey2{*silkworm::from_hex("6951c35e335fa18c97cb207119133cd8009580cd00000000005279a8")};
    static Bytes kAccountHistoryValue2{*silkworm::from_hex(
        "0100000000000000000000003a3000000700000044000a004600010048000100490005004c0001004d0001005e"
        "00000040000000560000005a0000005e0000006a0000006e000000720000005da562a563a565a567a56aa59da5"
        "a0a5f0a5f5a57ef926a863a8eb520b535d1b951bb71b3c1c741caa4f53f5b0f5184f536018f6")};

    static Bytes kAccountHistoryKey3{*silkworm::from_hex("000000000000000000000000000000000000000000000000005279a8")};
    static Bytes kAccountHistoryValue3{*silkworm::from_hex(
        "0100000000000000000000003b30270000000040202b003f002c001c002d0009002e000a002f000000300000003100000032000b003300"
        "0200340011003500030036000a003700040038000800390000003a0000003b0007003c0000003d000a003e0003003f0002004000060041"
        "000200420002004300010044000200450003004700050048000400490039004a0012004b0003004c0012004d00c2004e0010004f000500"
        "50007a0051001700520000005300650049010000c901000003020000170200002d0200002f02000031020000330200004b020000510200"
        "00750200007d020000930200009d020000af020000b1020000b3020000c3020000c5020000db020000e3020000e9020000f7020000fd02"
        "000003030000070300000d03000015030000210300002b0300009f030000c5030000cd030000f3030000790500009b050000a70500009d"
        "060000c3060000c5060000988d9b8d9c8d9d8d9f8da08da18da38da48da58da68da78da88da98dab8dac8dad8dae8daf8db08db18db28d"
        "b38db48db58dba8dbb8dbc8dbd8dbe8dbf8dc18dc28dc38dc48dc58dc68dc88dc98dca8d598fa7a2f6a2f9a207a344a3c8a331a446a423"
        "ad27ad37ae3cae40ae58ee5aee61eeb8eebeee44ef91ef9cef23f189f1c403ec033c047905b605d4120d133b147d147b168616641a5624"
        "c2cec6dce5dcd7df25e02ee071e093e0a2e00ae11de344e387e3a3e3abe37de43b249824413f5741734203549654a554bc5419db204529"
        "4530454c45d4abf0ab05ac0cac13ac18ac00b9dfb63f7fe3535bc76de078e080e088e095e09ce0a7e0aee0b4e0b8e0bde014431a4306a6"
        "d625e025ed25ff252e39ed3916722972497258725f7250735f738e749b74587c9b7c7da001657983a0d5a9d5c91fcd1f1a2046216d4975"
        "4a084bef6cf376418d8f8d113f4b49a1491a4db5e9ec542355a35c816b9a6cc3719e791c8909b4ce45f817bf4c074de94dfb4d154e1a4e"
        "1e4e714fa6b183bd84bd87bd8cbd8fbdc0bdabc0b8c0dbc0ebc011c5740543065c06630666436843754341754975f6a5a7ccf7e71aec2e"
        "fab12676415dfb73f280f287f2040f21369b5818863c86a5b2b4b2bab2afb4277fdf7ff27ff97fbd80cf808da643a80db4dbe3d2ff6511"
        "69116b116d116e1171117311d813f5138f149214c8142615411544156a1575157d157e15a415a515f31777448e44ba4d3155625b685b35"
        "5c425c585c465de15dd26b4f7250726072219328935d935e93a193e493e593e693ee93ef93f893fa931b941c94f3abb4aebeaeb2af6cb5"
        "fccc29cf09004cb4000037be000039be00003bbe09005dd1000060d1000062d100007fea010068eb0000af2b2442a79900d99e367b394d"
        "5fa17448c94dc98bcbe0cdf7cd74ce7dce86ceeecefece12cf30cf36cf3ccf49cf630a9c0a2025b93608500f5023502a502b5035503d50"
        "3e5043504b504d504e5054505650d250d750dd50e450e950f250f750fe5003510d6214621a621f6225622b62336235623a624162426247"
        "624c62556262626b6271627d6282628d6294629a62a162aa62b362b962bf62c462ca62ce62d662d762df62e762ee62f762ff6201630663"
        "0d6316631b632063286331633a6343634963506355635b6361636463706375637e63866387638f6394639a63a063a663ae63b463ba63c1"
        "63c663cb63d163db63e263e963ee63f363f863d78172947b948494899496949d94a494ad94b194b894be94c394cc94d594dd94e294e794"
        "ef94f694fb94029507950d9514951a951f9526952e9538953d9549954f9558955c9561956c95749577958095859592959795a395ad95b4"
        "95ba95bb95c195c895d195d695e395e895ee95f595fb95049610961696229628962e9634963d9646964f96549605975b97bd9714a234a7"
        "50c16fc501d80ad814d82cd841d84bd863d870d87cd84de3c3e989fb93fba7fbc9fefffe54ffdb07fb3f664f9c5099587d8a418b888be4"
        "8e2a90e49d91b59ddfd7e55be61de86ef3f1096579667a0a7def8bbcbb0b0f3b16974265537753895392539b53a453ad53b653d153da53"
        "e853f053f553fe530754105422542b5434543d5446544b54505461546a5473547c5485549754a054bb54c454ce54de54e654f154fa5403"
        "55095515551e55275542555d5578559c55a555aa55b355c055c555db55ed55f655fe550356085611561a5623562c5635563e5662566b56"
        "745686568f569856a156b356bc56c556ce56f256fb5604570a571f57315743574c575e577057795781578b5794579d57a657af57c157dc"
        "57e557f457fc57095819581b5824582d583b584858515862586c5875587e589958a058ab58b458bd58aa5a635dbc5dd65d568bc79a279b"
        "09000f770300147704001e770800287700003ba1000042be0000e2be0000fbbe0000edc500001b369f2b7444cf78de78327938793f7944"
        "794c79517957795c79637968796d79727979797e79837989798e79957996799d79aa79ab79b079b679bd79c279c779cf79d479da79db79"
        "e179e679ec79f379f879017a037a067a0d7a0e7a137a187a1f7a207a287a2d7a327a387a3d7a447a4a7a567a5b7a617a687afc7a017b08"
        "7b0e7b137b197b257b377b437b497b557b5f7b6a7b6c7b6d7b8d7b9f7ba97baf7bb57bbe7bc47bc57bd57bad7db37dbe7dbf7dd17de57d"
        "f17dfb7d017e0b7e157e207e287e2b7e397e4b7e517e5f7e")};

    static Bytes kAccountChangeSetKey{*silkworm::from_hex("00000000005279ad")};
    static Bytes kAccountChangeSetSubkey{*silkworm::from_hex("578f0a154b23be77fc2033197fbc775637648ad4")};
    static Bytes kAccountChangeSetValue{*silkworm::from_hex("03012f090207fbc719f215d705")};

    static Bytes kPlainStateKey{*silkworm::from_hex("6951c35e335fa18c97cb207119133cd8009580cd")};

    static Bytes kAccountChangeSetKey1{*silkworm::from_hex("00000000005EF618")};
    static Bytes kAccountChangeSetSubkey1{*silkworm::from_hex("6951c35e335fa18c97cb207119133cd8009580cd")};
    static Bytes kAccountChangeSetValue1{*silkworm::from_hex("00000000005279a8")};

    static Bytes kAccountChangeSetKey2{*silkworm::from_hex("0000000000532b9f")};
    static Bytes kAccountChangeSetSubkey2{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes kAccountChangeSetValue2{*silkworm::from_hex("020944ed67f28fd50bb8e9")};

    auto& tx = transaction;
    EXPECT_CALL(transaction, create_state(_, _, _)).Times(2).WillRepeatedly(Invoke([&tx](auto& ioc, const auto& storage, auto block_number) -> std::shared_ptr<State> {
        return std::make_shared<db::state::RemoteState>(ioc, tx, storage, block_number);
    }));

    EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            SILK_DEBUG << "EXPECT_CALL::get_one "
                       << " table: " << db::table::kCanonicalHashesName
                       << " key: " << silkworm::to_hex(kZeroKey)
                       << " value: " << silkworm::to_hex(kZeroHeader);
            co_return kZeroHeader;
        }));
    EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kConfigName
                       << " key: " << silkworm::to_hex(kConfigKey)
                       << " value: " << silkworm::to_hex(kConfigValue);
            co_return kConfigValue;
        }));
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey1)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue1);
            co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey},
                               silkworm::ByteView{kAccountChangeSetSubkey}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue);
            co_return kAccountChangeSetValue;
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1},
                               silkworm::ByteView{kAccountChangeSetSubkey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey1)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey1)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue1);
            co_return kAccountChangeSetValue1;
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2},
                               silkworm::ByteView{kAccountChangeSetSubkey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey2)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey2)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue2);
            co_return kAccountChangeSetValue2;
        }));
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey2)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue2);
            co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
        }));
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey3)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue3);
            co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
        }));
    EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kPlainStateName
                       << " key: " << silkworm::to_hex(kPlainStateKey)
                       << " value: ";
            co_return Bytes{};
        }));

    BlockNum block_number = 5'405'095;  // 0x5279A7

    Call call;
    call.from = 0x578f0a154b23be77fc2033197fbc775637648ad4_address;
    call.value = 0;
    call.gas = 211'190;
    call.gas_price = 14;
    call.data = *silkworm::from_hex(
        "0x414bf3890000000000000000000000009d381f0b1637475f133c92d9b9fdc5493ae19b630000000000000000000000009b73fc19"
        "3bfa16abe18d1ea30734e4a6444a753f00000000000000000000000000000000000000000000000000000000000027100000000000"
        "00000000000000578f0a154b23be77fc2033197fbc775637648ad40000000000000000000000000000000000000000000000000000"
        "0000612ba19c00000000000000000000000000000000000000000001a784379d99db42000000000000000000000000000000000000"
        "00000000000002cdc48e6cca575707722c0000000000000000000000000000000000000000000000000000000000000000");

    silkworm::Block block{};
    block.header.number = block_number;

    TraceConfig config{true, true, true};
    TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
    const auto result = spawn_and_wait(executor.trace_call(block, call, config));

    CHECK(result.pre_check_error.has_value() == false);
    CHECK(nlohmann::json(result.traces) == R"({
        "output": "0x",
        "stateDiff": {
            "0x0000000000000000000000000000000000000000": {
            "balance": {
                "*": {
                "from": "0x44ed67f28fd50bb8e9",
                "to": "0x44ed67f28fd538d65d"
                }
            },
            "code": "=",
            "nonce": "=",
            "storage": {}
            },
            "0x578f0a154b23be77fc2033197fbc775637648ad4": {
            "balance": "=",
            "code": "=",
            "nonce": {
                "*": {
                "from": "0x2f",
                "to": "0x30"
                }
            },
            "storage": {}
            }
        },
        "trace": [
            {
            "action": {
                "callType": "call",
                "from": "0x578f0a154b23be77fc2033197fbc775637648ad4",
                "gas": "0x261b2",
                "input": "0x",
                "to": "0x6951c35e335fa18c97cb207119133cd8009580cd",
                "value": "0x0"
            },
            "error": "invalid opcode: opcode 0x4b not defined",
            "result": null,
            "subtraces": 0,
            "traceAddress": [],
            "type": "call"
            }
        ],
        "vmTrace": {
            "code": "0x414bf3890000000000000000000000009d381f0b1637475f133c92d9b9fdc5493ae19b630000000000000000000000009b73fc193bfa16abe18d1ea30734e4a6444a753f0000000000000000000000000000000000000000000000000000000000002710000000000000000000000000578f0a154b23be77fc2033197fbc775637648ad400000000000000000000000000000000000000000000000000000000612ba19c00000000000000000000000000000000000000000001a784379d99db4200000000000000000000000000000000000000000000000002cdc48e6cca575707722c0000000000000000000000000000000000000000000000000000000000000000",
            "ops": [
            {
                "cost": 2,
                "ex": {
                "mem": null,
                "push": ["0x0"],
                "store": null,
                "used": 156080
                },
                "idx": "0",
                "op": "COINBASE",
                "pc": 0,
                "sub": null
            },
            {
                "cost": 0,
                "ex": {
                "mem": null,
                "push": [],
                "store": null,
                "used": 156080
                },
                "idx": "1",
                "op": "opcode 0x4b not defined",
                "pc": 1,
                "sub": null
            }
            ]
        }
    })"_json);
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_calls") {
    static Bytes kAccountHistoryKey1{*silkworm::from_hex("e0a2bd4258d2768837baa26a28fe71dc079f84c700000000005279a8")};
    static Bytes kAccountHistoryValue1{*silkworm::from_hex(
        "0100000000000000000000003a300000010000005200c003100000008a5e905e9c5ea55ead5eb25eb75ebf5ec95ed25ed75ee15eed5ef25efa"
        "5eff5e085f115f1a5f235f2c5f355f3e5f475f505f595f625f6b5f745f7c5f865f8f5f985fa15faa5faf5fb45fb95fc15fce5fd75fe05fe65f"
        "f25ffb5f04600d6016601f602860306035603a6043604c6055605a606760706079607f608b6094609d60a560af60b860c160ca60d360db60e5"
        "60ee60f460fb600061096111611b6124612d6136613f61486151615a6160616c6175617e6187618f619961a261ab61b461bb61c661cc61d861"
        "e161ea61f361fc6102620e6217622062296230623a6241624d6256625f6271627a6283628c6295629e62a762b062b662c262ca62d462dc62e6"
        "62ef62f86201630a6313631c6325632e63376340634963526358635e6364636a6374637d6388639663a163ac63b563bc63c463ca63d063d963"
        "df63e563eb63f163fd6306640d641264186421642a6433643c6445644c64516457645d64646469647264776484648d6496649f64a864b164c3"
        "64cc64d164de64e764ee64f96402650b6514651d6526652f6538653d6547654d6553655c6565656e657765886592659b65a465ad65b665bf65"
        "c665cb65d165da65e365ec65f565fe6507661066196622662b6634663d6646664f6658666166676672667c6685668e669766a066a966b266bb"
        "66c466ca66d666df66e866f166f766fc6603670c6715671e6724673067386742674b67516757675d6766676f67786781678a678f6796679c67"
        "a167ae67b767c067c967d267e167ed67f667ff67086810681a682368296835683e684768506859685e686b6874687d6886688f689868a168aa"
        "68b368bc68c568ce68e068e968f268fb6804690d6916691f69266931693a6943694c6955695e6967697069796982698b6994699d69a669af69"
        "b869c169ca69d369dc69e569ee69f769fe69086a126a1b6a246a366a3f6a486a516a5a6a636a6c6a7e6a876a906a966aa26aab6ab46abd6ac6"
        "6acf6ad56adb6ae16aea6af36afc6a056b0e6b176b206b296b326b3b6b416b4b6b566b5c6b676b716b7a6b806b886b956b9e6ba76bb06bb96b"
        "bf6bc56bcb6bd06bd56bdd6be66bef6b016c0a6c136c1c6c226c2d6c346c406c496c526c5a6c646c6d6c766c7f6c886c916c966c9c6ca36cac"
        "6cb56cbe6cc76cd06cd96ce26ce86cf16cfd6c066d0f6d186d216d2a6d336d3c6d456d4e6d576d606d696d726d7b6d846d8a6d966d9f6da46d"
        "b16dba6dc36dcc6dd56dde6de76df06df76d026e096e146e1d6e266e2f6e386e416e4a6e516e5c6e656e6c6e746e806e896e906e9b6ea46ead"
        "6eb76ebf6ec86ed16eda6ee36eec6ef56efe6e076f0d6f196f226f2b6f346f3d6f466f4f6f586f616f666f706f776f7c6f856f8e6f976f9e6f"
        "a96fb26fb96fc46fcd6fd66fdc6fe36fe86ff16ffa6fff6f0c7015701e702670397042704b70527058705d7066706f70787081708a7093709a"
        "70a570ae70b770c070c970d170d970e470ed70f670fc7008711271197123712c7135713e714771597162716b7174717a7186718f719871a171"
        "aa71b371bc71c571ce71d771e071f271fb7104720d7216721f72287231723a7240724c7255725b7267726d7279728272897291729d72a672ac"
        "72b872c072ca72d372d972e572ee72f772007309731273197324732d7336733f73487351735a7363736c7375737a73877390739973a273ab73"
        "b473bd73c673cf73d873e173e773ee73f373fc7305740a7419742074297432743b7444744d7456745f746b747174797483748c7495749e74a7"
        "74b074b974c274cb74d074d774dd74e374ee74f87401750a7513751c7525752e7537754975527558755f7564756d7576757f75877591759a75"
        "a375aa75af75b575be75c775d075d975e275eb75f475fd750676187621762a7632763c7645764d7657766076697672767b7683768d7696769f"
        "76a876b176ba76c376cc76d576de76e776f076f97602770b7714771d7724772f77387741774a7753775c7765776e7774778077897792779b77"
        "a477aa77b177b677bf77c577d177da77e377e977f077f577fe7707781078197822782b7834783d7846784f78587861786a7873787c7885788e"
        "789778a078a878b178b878c478cd78d678df78e878f178fa7803790c7915791e7924793079387942794b7954795d7963796e79787981798979"
        "8e7993799879a579ab79b779c079c979d279db79e479ed79f679ff79087a117a1a7a237a2b7a357a3c7a447a507a597a627a6b7a747a7d7a86"
        "7a8f7a987aa17aaa7ab37abc7ac57ace7ad57ae07ae97aee7af87a017b0d7b167b1f7b287b2e7b377b3e7b437b4c7b557b5e7b677b707b797b"
        "827b8b7b947b9a7ba37baf7bb57bbc7bc17bca7bd37bdc7be47bea7bf57b007c097c0f7c197c217c2d7c367c3f7c487c517c5a7c637c6c7c75"
        "7c7e7c877c907c997ca17cab7cb27cb87cbd7cc67ccf7cd67ce17cea7cf37cfc7c057d0b7d177d207d297d317d3b7d417d4d7d537d5f7d657d"
        "6d7d777d837d8c7d957d9e7da77db07db97dc27dcb7dd27dd77ddd7de67def7df87d017e0a7e137e1c7e257e2e7e377e407e497e4f7e557e5b"
        "7e647e6a7e727e7f7e887e917e967ea37eac7eb57ebe7ec77ed07ed67ee27eeb7ef47efd7e037f0f7f187f217f2a7f337f3c7f457f4e7f577f"
        "607f667f727f7b7f847f8d7f")};

    static Bytes kAccountHistoryKey2{*silkworm::from_hex("52728289eba496b6080d57d0250a90663a07e55600000000005279a8")};
    static Bytes kAccountHistoryValue2{*silkworm::from_hex("0100000000000000000000003a300000010000004e00000010000000d63b")};

    static Bytes kAccountHistoryKey3{*silkworm::from_hex("000000000000000000000000000000000000000000000000005279a8")};
    static Bytes kAccountHistoryValue3{*silkworm::from_hex(
        "0100000000000000000000003b30270000000040202b003f002c001c002d0009002e000a002f000000300000003100000032000b003300"
        "0200340011003500030036000a003700040038000800390000003a0000003b0007003c0000003d000a003e0003003f0002004000060041"
        "000200420002004300010044000200450003004700050048000400490039004a0012004b0003004c0012004d00c2004e0010004f000500"
        "50007a0051001700520000005300650049010000c901000003020000170200002d0200002f02000031020000330200004b020000510200"
        "00750200007d020000930200009d020000af020000b1020000b3020000c3020000c5020000db020000e3020000e9020000f7020000fd02"
        "000003030000070300000d03000015030000210300002b0300009f030000c5030000cd030000f3030000790500009b050000a70500009d"
        "060000c3060000c5060000988d9b8d9c8d9d8d9f8da08da18da38da48da58da68da78da88da98dab8dac8dad8dae8daf8db08db18db28d"
        "b38db48db58dba8dbb8dbc8dbd8dbe8dbf8dc18dc28dc38dc48dc58dc68dc88dc98dca8d598fa7a2f6a2f9a207a344a3c8a331a446a423"
        "ad27ad37ae3cae40ae58ee5aee61eeb8eebeee44ef91ef9cef23f189f1c403ec033c047905b605d4120d133b147d147b168616641a5624"
        "c2cec6dce5dcd7df25e02ee071e093e0a2e00ae11de344e387e3a3e3abe37de43b249824413f5741734203549654a554bc5419db204529"
        "4530454c45d4abf0ab05ac0cac13ac18ac00b9dfb63f7fe3535bc76de078e080e088e095e09ce0a7e0aee0b4e0b8e0bde014431a4306a6"
        "d625e025ed25ff252e39ed3916722972497258725f7250735f738e749b74587c9b7c7da001657983a0d5a9d5c91fcd1f1a2046216d4975"
        "4a084bef6cf376418d8f8d113f4b49a1491a4db5e9ec542355a35c816b9a6cc3719e791c8909b4ce45f817bf4c074de94dfb4d154e1a4e"
        "1e4e714fa6b183bd84bd87bd8cbd8fbdc0bdabc0b8c0dbc0ebc011c5740543065c06630666436843754341754975f6a5a7ccf7e71aec2e"
        "fab12676415dfb73f280f287f2040f21369b5818863c86a5b2b4b2bab2afb4277fdf7ff27ff97fbd80cf808da643a80db4dbe3d2ff6511"
        "69116b116d116e1171117311d813f5138f149214c8142615411544156a1575157d157e15a415a515f31777448e44ba4d3155625b685b35"
        "5c425c585c465de15dd26b4f7250726072219328935d935e93a193e493e593e693ee93ef93f893fa931b941c94f3abb4aebeaeb2af6cb5"
        "fccc29cf09004cb4000037be000039be00003bbe09005dd1000060d1000062d100007fea010068eb0000af2b2442a79900d99e367b394d"
        "5fa17448c94dc98bcbe0cdf7cd74ce7dce86ceeecefece12cf30cf36cf3ccf49cf630a9c0a2025b93608500f5023502a502b5035503d50"
        "3e5043504b504d504e5054505650d250d750dd50e450e950f250f750fe5003510d6214621a621f6225622b62336235623a624162426247"
        "624c62556262626b6271627d6282628d6294629a62a162aa62b362b962bf62c462ca62ce62d662d762df62e762ee62f762ff6201630663"
        "0d6316631b632063286331633a6343634963506355635b6361636463706375637e63866387638f6394639a63a063a663ae63b463ba63c1"
        "63c663cb63d163db63e263e963ee63f363f863d78172947b948494899496949d94a494ad94b194b894be94c394cc94d594dd94e294e794"
        "ef94f694fb94029507950d9514951a951f9526952e9538953d9549954f9558955c9561956c95749577958095859592959795a395ad95b4"
        "95ba95bb95c195c895d195d695e395e895ee95f595fb95049610961696229628962e9634963d9646964f96549605975b97bd9714a234a7"
        "50c16fc501d80ad814d82cd841d84bd863d870d87cd84de3c3e989fb93fba7fbc9fefffe54ffdb07fb3f664f9c5099587d8a418b888be4"
        "8e2a90e49d91b59ddfd7e55be61de86ef3f1096579667a0a7def8bbcbb0b0f3b16974265537753895392539b53a453ad53b653d153da53"
        "e853f053f553fe530754105422542b5434543d5446544b54505461546a5473547c5485549754a054bb54c454ce54de54e654f154fa5403"
        "55095515551e55275542555d5578559c55a555aa55b355c055c555db55ed55f655fe550356085611561a5623562c5635563e5662566b56"
        "745686568f569856a156b356bc56c556ce56f256fb5604570a571f57315743574c575e577057795781578b5794579d57a657af57c157dc"
        "57e557f457fc57095819581b5824582d583b584858515862586c5875587e589958a058ab58b458bd58aa5a635dbc5dd65d568bc79a279b"
        "09000f770300147704001e770800287700003ba1000042be0000e2be0000fbbe0000edc500001b369f2b7444cf78de78327938793f7944"
        "794c79517957795c79637968796d79727979797e79837989798e79957996799d79aa79ab79b079b679bd79c279c779cf79d479da79db79"
        "e179e679ec79f379f879017a037a067a0d7a0e7a137a187a1f7a207a287a2d7a327a387a3d7a447a4a7a567a5b7a617a687afc7a017b08"
        "7b0e7b137b197b257b377b437b497b557b5f7b6a7b6c7b6d7b8d7b9f7ba97baf7bb57bbe7bc47bc57bd57bad7db37dbe7dbf7dd17de57d"
        "f17dfb7d017e0b7e157e207e287e2b7e397e4b7e517e5f7e")};

    static Bytes kAccountChangeSetKey{*silkworm::from_hex("00000000005279ab")};
    static Bytes kAccountChangeSetSubkey{*silkworm::from_hex("e0a2bd4258d2768837baa26a28fe71dc079f84c7")};
    static Bytes kAccountChangeSetValue{*silkworm::from_hex("030203430b141e903194951083c424fd")};

    static Bytes kAccountChangeSetKey1{*silkworm::from_hex("0000000000532b9f")};
    static Bytes kAccountChangeSetSubkey1{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes kAccountChangeSetValue1{*silkworm::from_hex("020944ed67f28fd50bb8e9")};

    static Bytes kPlainStateKey1{*silkworm::from_hex("e0a2bd4258d2768837baa26a28fe71dc079f84c7")};
    static Bytes kPlainStateKey2{*silkworm::from_hex("52728289eba496b6080d57d0250a90663a07e556")};

    auto& tx = transaction;
    EXPECT_CALL(transaction, create_state(_, _, _)).Times(2).WillRepeatedly(Invoke([&tx](auto& ioc, const auto& storage, auto block_number) -> std::shared_ptr<State> {
        return std::make_shared<db::state::RemoteState>(ioc, tx, storage, block_number);
    }));

    SECTION("callMany: failed with intrinsic gas too low") {
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));

        const auto block_number = 5'405'095;  // 0x5279A7

        TraceCall trace_call;
        trace_call.call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        trace_call.call.gas = 50'000;
        trace_call.call.gas_price = 7;
        trace_call.call.data = *silkworm::from_hex("602a60005500");
        trace_call.trace_config = TraceConfig{false, false, false};

        std::vector<TraceCall> calls;
        calls.push_back(trace_call);

        silkworm::Block block{};
        block.header.number = block_number;

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_calls(block, calls));

        CHECK(result.pre_check_error.has_value() == true);
        CHECK(result.pre_check_error.value() == "first run for txIndex 0 error: intrinsic gas too low: have 50000, want 53072");
    }

    SECTION("Call: full output") {
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey}, silkworm::ByteView{kAccountChangeSetSubkey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue;
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1}, silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue1;
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));

        const auto block_number = 5'405'095;  // 0x5279A7
        TraceCall trace_call;
        trace_call.call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        trace_call.call.gas = 118'936;
        trace_call.call.gas_price = 7;
        trace_call.call.data = *silkworm::from_hex("602a60005500");
        trace_call.trace_config = TraceConfig{true, true, true};

        std::vector<TraceCall> calls;
        calls.push_back(trace_call);

        silkworm::Block block{};
        block.header.number = block_number;

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_calls(block, calls));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"([
            {
                "output": "0x",
                "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                    "balance": {
                    "*": {
                        "from": "0x44ed67f28fd50bb8e9",
                        "to": "0x44ed67f28fd513c08f"
                    }
                    },
                    "code": "=",
                    "nonce": "=",
                    "storage": {}
                },
                "0x52728289eba496b6080d57d0250a90663a07e556": {
                    "balance": {
                    "+": "0x0"
                    },
                    "code": {
                    "+": "0x"
                    },
                    "nonce": {
                    "+": "0x1"
                    },
                    "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": {
                        "+": "0x000000000000000000000000000000000000000000000000000000000000002a"
                    }
                    }
                },
                "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7": {
                    "balance": "=",
                    "code": "=",
                    "nonce": {
                    "*": {
                        "from": "0x343",
                        "to": "0x344"
                    }
                    },
                    "storage": {}
                }
                },
                "trace": [
                {
                    "action": {
                    "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                    "gas": "0x10148",
                    "init": "0x602a60005500",
                    "value": "0x0"
                    },
                    "result": {
                    "address": "0x52728289eba496b6080d57d0250a90663a07e556",
                    "code": "0x",
                    "gasUsed": "0x565a"
                    },
                    "subtraces": 0,
                    "traceAddress": [],
                    "type": "create"
                }
                ],
                "vmTrace": {
                "code": "0x602a60005500",
                "ops": [
                    {
                    "cost": 3,
                    "ex": {
                        "mem": null,
                        "push": [
                        "0x2a"
                        ],
                        "store": null,
                        "used": 65861
                    },
                    "idx": "0-0",
                    "op": "PUSH1",
                    "pc": 0,
                    "sub": null
                    },
                    {
                    "cost": 3,
                    "ex": {
                        "mem": null,
                        "push": [
                        "0x0"
                        ],
                        "store": null,
                        "used": 65858
                    },
                    "idx": "0-1",
                    "op": "PUSH1",
                    "pc": 2,
                    "sub": null
                    },
                    {
                    "cost": 22100,
                    "ex": {
                        "mem": null,
                        "push": [],
                        "store": {
                        "key": "0x0",
                        "val": "0x2a"
                        },
                        "used": 43758
                    },
                    "idx": "0-2",
                    "op": "SSTORE",
                    "pc": 4,
                    "sub": null
                    },
                    {
                    "cost": 0,
                    "ex": {
                        "mem": null,
                        "push": [],
                        "store": null,
                        "used": 43758
                    },
                    "idx": "0-3",
                    "op": "STOP",
                    "pc": 5,
                    "sub": null
                    }
                ]
                }
            }
        ])"_json);
    }
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_block_transactions") {
    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes kAccountHistoryKey1{*silkworm::from_hex("a85b4c37cd8f447848d49851a1bb06d10d410c1300000000000fa0a5")};
    static Bytes kAccountHistoryValue1{*silkworm::from_hex("0100000000000000000000003a300000010000000f00000010000000a5a0")};

    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes kAccountHistoryKey2{*silkworm::from_hex("000000000000000000000000000000000000000000000000000fa0a5")};
    static Bytes kAccountHistoryValue2{*silkworm::from_hex(
        "0100000000000000000000003b301800000001000000000002000100040007000600030008000200090000000e0011000f00060011000f"
        "00130003001a0000001c0003001d0000001e0000001f00370020001d002100270222006b00230019002400320025004d00260004002700"
        "04002a000f002b002700d0000000d2000000d6000000e6000000ee000000f4000000f60000001a01000028010000480100005001000052"
        "0100005a0100005c0100005e010000ce0100000a02000000050000d80500000c060000720600000e070000180700002207000042070000"
        "0000d03cd13cd1b6d3b617b718b719b72ab72cb774fa4611c695c795c8957184728474842d12377d4c7d547d767e848053819c81dc81d9"
        "8fee8f059022902f9035903c903f904a9091902eb0fee1ffe101e202e203e205e2e6b1e8b1e9b1eab1edb1eeb1f0b1f1b1f2b1f3b1f5b1"
        "f6b1f7b1f9b1fab1fcb1de62e562e662f2625209b453ba53c153d65304ebb1007f4b8a4b314c9b4c685dc25dcc5df05d045e0c5e315e51"
        "5eb55e0f5f105f2d5fac890f9031907f907e9f0ca0f1a0f6a0faa009a120a126a1f3a1f5a1b1a2b3a21ca41fa425a445a456a458a443a5"
        "95a698a68ad190d1a1e249e577e570e6c3e936f940f921fe28fe2dfe27ff39ff83ff25123612371230439f434d598c593d6c676c996ca0"
        "6cc16cf26c337114826183e386f59729983b9870f284f2a2f283f3a1f3b7f3faf702f84cfa53fabd00d4070000d8070000dd0700000c08"
        "0000730800007f080000c20c00003b1e00003f1e0000671e00006a1e0000ea200000fd200100f8230000ac240000333600008d3600009d"
        "370000673a00000c3b00000b520000105200004d540200c2690000ce690100eb690100ee690000176a0400f9770000d4780000de780000"
        "e478000076790000de790100e1790200007a0100037a0200297a04005b7c0a00677c04006d7c00006f7c0600777c0000797c0600817c00"
        "00837c06008b7c00008d7c0600957c0000977c06009f7c0400a57c0200a97c0000ab7c0500b37c0700bd7c0000bf7c0400c57c0300eb7c"
        "0000f97c0100017d0000057d00000d7d00001c7d0300217d08002b7d00002d7d0600357d0000377d06003f7d0000417d0500497d070053"
        "7d0400597d02005d7d0000607d0500677d0000697d0800737d08007e7d0500857d0000877d0300ba7d0000bd7d0000cc7d0000d47d0000"
        "118e0000978e0000aa8e0000128f0300178f0000198f0700238f0300288f0100408f0100438f06004b8f0400518f08005b8f01005e8f08"
        "00698f00006b8f01006e8f0300748f07007d8f0000808f0300858f0000878f03008c8f0500948f020024900100279001002a9000002c90"
        "020031900000349002003a9002003f9001004290000045900300759000001c91000013a8000023a8000043a8000055aa0000adab0100ca"
        "bd0000b9c20000d9c20000e2c20000f8c2000031d100004ed1000051d1000062d1040068d1070071d109007cd1050084d105008bd10800"
        "95d1000097d106009fd10000a1d10100a4d10300abd10100aed10300b3d10000b5d10000b7d10400bdd10000bfd10200c3d10200c7d100"
        "00cad10200ced10600f6d100007bd20000afd2000038d402006cd4000086d402008ad401008dd400008fd40100c6d5000099d60600a1d6"
        "0400a7d60000a9d60000acd60000aed60100c7d60000d4d60500dbd60200f2d60100f5d60200fad6020010d7010013d7030019d700001b"
        "d701001ed7050025d704002bd7080035d70600a1d80000bad80000701777178b1793179b17ca17db1708181a1829183a183c183d183f18"
        "7a1a811a941a9b1a2f1b371b3a1b514451475d4763477047f147f84701480748114818481c482f483d4843484b48ec59d45a6c5b0f5dca"
        "716f72707271721ba320a37fa585a5c6b6f9b6fbb604b752b899b8b8b8e6b83eb98fb990b991b9bfbac7ba33ca47ca8ecb93cb58cc5fcc"
        "f7cd6ed3c9d6ccd6d5d6a5e4b5e4d6e46fe58be596e597e598e599e59be59ce59ee59fe5a0e5a1e5aae5ace5b4e5b5e5b6e5bbe5bce5bd"
        "e5c0e5c7e5c8e5ece5ede5eee5fae6ffe65cf6e3f7b4f9160e89108a109310aa100d118412ad5681669a669c66f86646675d679f67e067"
        "1c68d86aa26dba6dba81c881b0820298219a40edb809cb09d909b60ad10ac00b3b8f618f958fbc90fba420a53ba5d5baedba07bb40bbb2"
        "bbe2bb02bcd0bef0bf8bc08ec02ace40ce41ce38cfd8d181d4a1d4a3d4dce45be55ee567e572e578e590e59be5a1e5c0e5b8e6dbe693e8"
        "9ee8fbe925ea53eaf6ecd7eea02ab42ae82afa2a042b222bb33db43db63dd13dd23dd53dd83dd93dda3dff3e003f2b3f2c3f2e3f423f43"
        "3f443f4d3f4e3f1c4034402841b741d641e34114424f422d447944a444a944c444c844bd5537563e5644564f567a565b572458a669dd6b"
        "1071127129716c719c71d171ed7115725d74a982ad82ce82d182d68277c47dc40bc53ac767c78cc7bcc71cc823c828c82dc892caa2caa3"
        "cbbdcb39783e8391b992b93dffbb05c205728f928fb6c7b44a365b3f5b08b1f2c41bc52bc57dc592cafbca39cd79cd96f15af221f338f3"
        "c434a94baa4ba84d424e1252125af45e625f645f6e5f556357637a633e64cf64fb66fc66fd66fe66ff6601670267036704670567066708"
        "6709670a67a575f87a4b7b537b157dec7f938d948d958d968d")};

    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes kAccountHistoryKey3{*silkworm::from_hex("daae090d53f9ed9e2e1fd25258c01bac4dd6d1c500000000000fa0a5")};
    static Bytes kAccountHistoryValue3{*silkworm::from_hex(
        "0100000000000000000000003a300000020000000e0004000f0031001800000022000000eca7f4a7d3a9dea9dfa9fd1b191c301cb91cbe"
        "1cf21cfc1c0f1d141d261d801d911da61d00440e4a485f4f5f427b537baf7bb17bb57bb97bbf7bc57bc97bd87bda7be17be47be97bfa7b"
        "fe7b017c267c297c2c7c367c3a9d3b9d3d9d429d47a071a0a5a0aea0b4a0b8a0c3a0c9a0")};

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey1{*silkworm::from_hex("00000000000fa0a5")};
    static Bytes kAccountChangeSetSubkey1{*silkworm::from_hex("a85b4c37cd8f447848d49851a1bb06d10d410c13")};
    static Bytes kAccountChangeSetValue1{*silkworm::from_hex("")};

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey2{*silkworm::from_hex("00000000000fb02e")};
    static Bytes kAccountChangeSetSubkey2{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes kAccountChangeSetValue2{*silkworm::from_hex("0208028ded68c33d1401")};

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet
    static Bytes kAccountChangeSetKey3{*silkworm::from_hex("00000000000fa0a5")};
    static Bytes kAccountChangeSetSubkey3{*silkworm::from_hex("daae090d53f9ed9e2e1fd25258c01bac4dd6d1c5")};
    static Bytes kAccountChangeSetValue3{*silkworm::from_hex("030127080334e1d62a9e3440")};

    auto& tx = transaction;
    EXPECT_CALL(transaction, create_state(_, _, _)).Times(2).WillRepeatedly(Invoke([&tx](auto& ioc, const auto& storage, auto block_number) -> std::shared_ptr<State> {
        return std::make_shared<db::state::RemoteState>(ioc, tx, storage, block_number);
    }));

    EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            SILK_DEBUG << "EXPECT_CALL::get_one "
                       << " table: " << db::table::kCanonicalHashesName
                       << " key: " << silkworm::to_hex(kZeroKey)
                       << " value: " << silkworm::to_hex(kZeroHeader);
            co_return kZeroHeader;
        }));
    EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kConfigName
                       << " key: " << silkworm::to_hex(kConfigKey)
                       << " value: " << silkworm::to_hex(kConfigValue);
            co_return kConfigValue;
        }));
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey1)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue1);
            co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
        }));
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey2)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue2);
            co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
        }));
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey3)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue3);
            co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1},
                               silkworm::ByteView{kAccountChangeSetSubkey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey1)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey1)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue1);
            co_return kAccountChangeSetValue1;
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2},
                               silkworm::ByteView{kAccountChangeSetSubkey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey2)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey2)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue2);
            co_return kAccountChangeSetValue2;
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey3},
                               silkworm::ByteView{kAccountChangeSetSubkey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey3)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey3)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue3);
            co_return kAccountChangeSetValue3;
        }));

    BlockNum block_number = 1'024'165;  // 0xFA0A5

    silkworm::Block block{};
    block.header.number = block_number;

    silkworm::Transaction txn;
    txn.set_sender(0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5_address);
    txn.nonce = 27;
    txn.value = 0;
    txn.data = *silkworm::from_hex(
        "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004"
        "361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080"
        "fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060"
        "008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c"
        "60af2c64736f6c634300050a0032");
    txn.max_priority_fee_per_gas = 0x3b9aca00;
    txn.max_fee_per_gas = 0x3b9aca00;
    txn.gas_limit = 0x47b760;
    txn.type = TransactionType::kLegacy;

    block.transactions.push_back(txn);

    TraceConfig config{true, true, true};
    TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
    const auto result = spawn_and_wait(executor.trace_block_transactions(block, config));

    CHECK(nlohmann::json(result) == R"([
        {
            "output": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "stateDiff": {
            "0x0000000000000000000000000000000000000000": {
                "balance": {
                "*": {
                    "from": "0x28ded68c33d1401",
                    "to": "0x28e46f23db3ea01"
                }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
            },
            "0xa85b4c37cd8f447848d49851a1bb06d10d410c13": {
                "balance": {
                "+": "0x0"
                },
                "code": {
                "+": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032"
                },
                "nonce": {
                "+": "0x1"
                },
                "storage": {}
            },
            "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5": {
                "balance": {
                "*": {
                    "from": "0x334e1d62a9e3440",
                    "to": "0x334884cb0275e40"
                }
                },
                "code": "=",
                "nonce": {
                "*": {
                    "from": "0x27",
                    "to": "0x28"
                }
                },
                "storage": {}
            }
            },
            "trace": [
            {
                "action": {
                "from": "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5",
                "gas": "0x46da7c",
                "init": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                "value": "0x0"
                },
                "result": {
                "address": "0xa85b4c37cd8f447848d49851a1bb06d10d410c13",
                "code": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                "gasUsed": "0xa3ab"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "create"
            }
            ],
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "vmTrace": {
            "code": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "ops": [
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x80"
                    ],
                    "store": null,
                    "used": 4643449
                },
                "idx": "0-0",
                "op": "PUSH1",
                "pc": 0,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x40"
                    ],
                    "store": null,
                    "used": 4643446
                },
                "idx": "0-1",
                "op": "PUSH1",
                "pc": 2,
                "sub": null
                },
                {
                "cost": 12,
                "ex": {
                    "mem": {
                    "data": "0x0000000000000000000000000000000000000000000000000000000000000080",
                    "off": 64
                    },
                    "push": [],
                    "store": null,
                    "used": 4643434
                },
                "idx": "0-2",
                "op": "MSTORE",
                "pc": 4,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x0"
                    ],
                    "store": null,
                    "used": 4643431
                },
                "idx": "0-3",
                "op": "PUSH1",
                "pc": 5,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x0",
                    "0x0"
                    ],
                    "store": null,
                    "used": 4643428
                },
                "idx": "0-4",
                "op": "DUP1",
                "pc": 7,
                "sub": null
                },
                {
                "cost": 2200,
                "ex": {
                    "mem": null,
                    "push": [],
                    "store": {
                    "key": "0x0",
                    "val": "0x0"
                    },
                    "used": 4641228
                },
                "idx": "0-5",
                "op": "SSTORE",
                "pc": 8,
                "sub": null
                },
                {
                "cost": 2,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x0"
                    ],
                    "store": null,
                    "used": 4641226
                },
                "idx": "0-6",
                "op": "CALLVALUE",
                "pc": 9,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x0",
                    "0x0"
                    ],
                    "store": null,
                    "used": 4641223
                },
                "idx": "0-7",
                "op": "DUP1",
                "pc": 10,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x1"
                    ],
                    "store": null,
                    "used": 4641220
                },
                "idx": "0-8",
                "op": "ISZERO",
                "pc": 11,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x14"
                    ],
                    "store": null,
                    "used": 4641217
                },
                "idx": "0-9",
                "op": "PUSH2",
                "pc": 12,
                "sub": null
                },
                {
                "cost": 10,
                "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641207
                },
                "idx": "0-10",
                "op": "JUMPI",
                "pc": 15,
                "sub": null
                },
                {
                "cost": 1,
                "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641206
                },
                "idx": "0-11",
                "op": "JUMPDEST",
                "pc": 20,
                "sub": null
                },
                {
                "cost": 2,
                "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641204
                },
                "idx": "0-12",
                "op": "POP",
                "pc": 21,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0xc6"
                    ],
                    "store": null,
                    "used": 4641201
                },
                "idx": "0-13",
                "op": "PUSH1",
                "pc": 22,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0xc6",
                    "0xc6"
                    ],
                    "store": null,
                    "used": 4641198
                },
                "idx": "0-14",
                "op": "DUP1",
                "pc": 24,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x23"
                    ],
                    "store": null,
                    "used": 4641195
                },
                "idx": "0-15",
                "op": "PUSH2",
                "pc": 25,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x0"
                    ],
                    "store": null,
                    "used": 4641192
                },
                "idx": "0-16",
                "op": "PUSH1",
                "pc": 28,
                "sub": null
                },
                {
                "cost": 36,
                "ex": {
                    "mem": {
                    "data": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                    "off": 0
                    },
                    "push": [],
                    "store": null,
                    "used": 4641156
                },
                "idx": "0-17",
                "op": "CODECOPY",
                "pc": 30,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x0"
                    ],
                    "store": null,
                    "used": 4641153
                },
                "idx": "0-18",
                "op": "PUSH1",
                "pc": 31,
                "sub": null
                },
                {
                "cost": 0,
                "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641153
                },
                "idx": "0-19",
                "op": "RETURN",
                "pc": 33,
                "sub": null
                }
            ]
            }
        }
    ])"_json);
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_block") {
    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes kAccountHistoryKey1{*silkworm::from_hex("a85b4c37cd8f447848d49851a1bb06d10d410c1300000000000fa0a5")};
    static Bytes kAccountHistoryValue1{*silkworm::from_hex("0100000000000000000000003a300000010000000f00000010000000a5a0")};

    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes kAccountHistoryKey2{*silkworm::from_hex("000000000000000000000000000000000000000000000000000fa0a5")};
    static Bytes kAccountHistoryValue2{*silkworm::from_hex(
        "0100000000000000000000003b301800000001000000000002000100040007000600030008000200090000000e0011000f00060011000f"
        "00130003001a0000001c0003001d0000001e0000001f00370020001d002100270222006b00230019002400320025004d00260004002700"
        "04002a000f002b002700d0000000d2000000d6000000e6000000ee000000f4000000f60000001a01000028010000480100005001000052"
        "0100005a0100005c0100005e010000ce0100000a02000000050000d80500000c060000720600000e070000180700002207000042070000"
        "0000d03cd13cd1b6d3b617b718b719b72ab72cb774fa4611c695c795c8957184728474842d12377d4c7d547d767e848053819c81dc81d9"
        "8fee8f059022902f9035903c903f904a9091902eb0fee1ffe101e202e203e205e2e6b1e8b1e9b1eab1edb1eeb1f0b1f1b1f2b1f3b1f5b1"
        "f6b1f7b1f9b1fab1fcb1de62e562e662f2625209b453ba53c153d65304ebb1007f4b8a4b314c9b4c685dc25dcc5df05d045e0c5e315e51"
        "5eb55e0f5f105f2d5fac890f9031907f907e9f0ca0f1a0f6a0faa009a120a126a1f3a1f5a1b1a2b3a21ca41fa425a445a456a458a443a5"
        "95a698a68ad190d1a1e249e577e570e6c3e936f940f921fe28fe2dfe27ff39ff83ff25123612371230439f434d598c593d6c676c996ca0"
        "6cc16cf26c337114826183e386f59729983b9870f284f2a2f283f3a1f3b7f3faf702f84cfa53fabd00d4070000d8070000dd0700000c08"
        "0000730800007f080000c20c00003b1e00003f1e0000671e00006a1e0000ea200000fd200100f8230000ac240000333600008d3600009d"
        "370000673a00000c3b00000b520000105200004d540200c2690000ce690100eb690100ee690000176a0400f9770000d4780000de780000"
        "e478000076790000de790100e1790200007a0100037a0200297a04005b7c0a00677c04006d7c00006f7c0600777c0000797c0600817c00"
        "00837c06008b7c00008d7c0600957c0000977c06009f7c0400a57c0200a97c0000ab7c0500b37c0700bd7c0000bf7c0400c57c0300eb7c"
        "0000f97c0100017d0000057d00000d7d00001c7d0300217d08002b7d00002d7d0600357d0000377d06003f7d0000417d0500497d070053"
        "7d0400597d02005d7d0000607d0500677d0000697d0800737d08007e7d0500857d0000877d0300ba7d0000bd7d0000cc7d0000d47d0000"
        "118e0000978e0000aa8e0000128f0300178f0000198f0700238f0300288f0100408f0100438f06004b8f0400518f08005b8f01005e8f08"
        "00698f00006b8f01006e8f0300748f07007d8f0000808f0300858f0000878f03008c8f0500948f020024900100279001002a9000002c90"
        "020031900000349002003a9002003f9001004290000045900300759000001c91000013a8000023a8000043a8000055aa0000adab0100ca"
        "bd0000b9c20000d9c20000e2c20000f8c2000031d100004ed1000051d1000062d1040068d1070071d109007cd1050084d105008bd10800"
        "95d1000097d106009fd10000a1d10100a4d10300abd10100aed10300b3d10000b5d10000b7d10400bdd10000bfd10200c3d10200c7d100"
        "00cad10200ced10600f6d100007bd20000afd2000038d402006cd4000086d402008ad401008dd400008fd40100c6d5000099d60600a1d6"
        "0400a7d60000a9d60000acd60000aed60100c7d60000d4d60500dbd60200f2d60100f5d60200fad6020010d7010013d7030019d700001b"
        "d701001ed7050025d704002bd7080035d70600a1d80000bad80000701777178b1793179b17ca17db1708181a1829183a183c183d183f18"
        "7a1a811a941a9b1a2f1b371b3a1b514451475d4763477047f147f84701480748114818481c482f483d4843484b48ec59d45a6c5b0f5dca"
        "716f72707271721ba320a37fa585a5c6b6f9b6fbb604b752b899b8b8b8e6b83eb98fb990b991b9bfbac7ba33ca47ca8ecb93cb58cc5fcc"
        "f7cd6ed3c9d6ccd6d5d6a5e4b5e4d6e46fe58be596e597e598e599e59be59ce59ee59fe5a0e5a1e5aae5ace5b4e5b5e5b6e5bbe5bce5bd"
        "e5c0e5c7e5c8e5ece5ede5eee5fae6ffe65cf6e3f7b4f9160e89108a109310aa100d118412ad5681669a669c66f86646675d679f67e067"
        "1c68d86aa26dba6dba81c881b0820298219a40edb809cb09d909b60ad10ac00b3b8f618f958fbc90fba420a53ba5d5baedba07bb40bbb2"
        "bbe2bb02bcd0bef0bf8bc08ec02ace40ce41ce38cfd8d181d4a1d4a3d4dce45be55ee567e572e578e590e59be5a1e5c0e5b8e6dbe693e8"
        "9ee8fbe925ea53eaf6ecd7eea02ab42ae82afa2a042b222bb33db43db63dd13dd23dd53dd83dd93dda3dff3e003f2b3f2c3f2e3f423f43"
        "3f443f4d3f4e3f1c4034402841b741d641e34114424f422d447944a444a944c444c844bd5537563e5644564f567a565b572458a669dd6b"
        "1071127129716c719c71d171ed7115725d74a982ad82ce82d182d68277c47dc40bc53ac767c78cc7bcc71cc823c828c82dc892caa2caa3"
        "cbbdcb39783e8391b992b93dffbb05c205728f928fb6c7b44a365b3f5b08b1f2c41bc52bc57dc592cafbca39cd79cd96f15af221f338f3"
        "c434a94baa4ba84d424e1252125af45e625f645f6e5f556357637a633e64cf64fb66fc66fd66fe66ff6601670267036704670567066708"
        "6709670a67a575f87a4b7b537b157dec7f938d948d958d968d")};

    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes kAccountHistoryKey3{*silkworm::from_hex("daae090d53f9ed9e2e1fd25258c01bac4dd6d1c500000000000fa0a5")};
    static Bytes kAccountHistoryValue3{*silkworm::from_hex(
        "0100000000000000000000003a300000020000000e0004000f0031001800000022000000eca7f4a7d3a9dea9dfa9fd1b191c301cb91cbe"
        "1cf21cfc1c0f1d141d261d801d911da61d00440e4a485f4f5f427b537baf7bb17bb57bb97bbf7bc57bc97bd87bda7be17be47be97bfa7b"
        "fe7b017c267c297c2c7c367c3a9d3b9d3d9d429d47a071a0a5a0aea0b4a0b8a0c3a0c9a0")};

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey1{*silkworm::from_hex("00000000000fa0a5")};
    static Bytes kAccountChangeSetSubkey1{*silkworm::from_hex("a85b4c37cd8f447848d49851a1bb06d10d410c13")};
    static Bytes kAccountChangeSetValue1{*silkworm::from_hex("")};

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey2{*silkworm::from_hex("00000000000fb02e")};
    static Bytes kAccountChangeSetSubkey2{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes kAccountChangeSetValue2{*silkworm::from_hex("0208028ded68c33d1401")};

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet
    static Bytes kAccountChangeSetKey3{*silkworm::from_hex("00000000000fa0a5")};
    static Bytes kAccountChangeSetSubkey3{*silkworm::from_hex("daae090d53f9ed9e2e1fd25258c01bac4dd6d1c5")};
    static Bytes kAccountChangeSetValue3{*silkworm::from_hex("030127080334e1d62a9e3440")};

    auto& tx = transaction;
    EXPECT_CALL(transaction, create_state(_, _, _)).Times(2).WillRepeatedly(Invoke([&tx](auto& ioc, const auto& storage, auto block_number) -> std::shared_ptr<State> {
        return std::make_shared<db::state::RemoteState>(ioc, tx, storage, block_number);
    }));

    EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            SILK_DEBUG << "EXPECT_CALL::get_one "
                       << " table: " << db::table::kCanonicalHashesName
                       << " key: " << silkworm::to_hex(kZeroKey)
                       << " value: " << silkworm::to_hex(kZeroHeader);
            co_return kZeroHeader;
        }));
    EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kConfigName
                       << " key: " << silkworm::to_hex(kConfigKey)
                       << " value: " << silkworm::to_hex(kConfigValue);
            co_return kConfigValue;
        }));

    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey1)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue1);
            co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
        }));
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey2)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue2);
            co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
        }));
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey3)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue3);
            co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1},
                               silkworm::ByteView{kAccountChangeSetSubkey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey1)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey1)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue1);
            co_return kAccountChangeSetValue1;
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2},
                               silkworm::ByteView{kAccountChangeSetSubkey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey2)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey2)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue2);
            co_return kAccountChangeSetValue2;
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey3},
                               silkworm::ByteView{kAccountChangeSetSubkey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey3)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey3)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue3);
            co_return kAccountChangeSetValue3;
        }));

    BlockNum block_number = 1'024'165;  // 0xFA0A5

    silkworm::BlockWithHash block_with_hash;
    block_with_hash.block.header.number = block_number;
    block_with_hash.hash = 0x527198f474c1f1f1d01129d3a17ecc17895d85884a31b05ef0ecd480faee1592_bytes32;

    silkworm::Transaction txn;
    txn.set_sender(0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5_address);
    txn.nonce = 27;
    txn.value = 0;
    txn.data = *silkworm::from_hex(
        "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004"
        "361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080"
        "fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060"
        "008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c"
        "60af2c64736f6c634300050a0032");
    txn.max_priority_fee_per_gas = 0x3b9aca00;
    txn.max_fee_per_gas = 0x3b9aca00;
    txn.gas_limit = 0x47b760;
    txn.type = TransactionType::kLegacy;

    block_with_hash.block.transactions.push_back(txn);

    TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};

    Filter filter;
    const auto result = spawn_and_wait(executor.trace_block(block_with_hash, filter));

    CHECK(nlohmann::json(result) == R"([
        {
            "action": {
            "from": "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5",
            "gas": "0x46da7c",
            "init": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "value": "0x0"
            },
            "blockHash": "0x527198f474c1f1f1d01129d3a17ecc17895d85884a31b05ef0ecd480faee1592",
            "blockNumber": 1024165,
            "result": {
            "address": "0xa85b4c37cd8f447848d49851a1bb06d10d410c13",
            "code": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "gasUsed": "0xa3ab"
            },
            "subtraces": 0,
            "traceAddress": [],
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "transactionPosition": 0,
            "type": "create"
        }
    ])"_json);
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_replayTransaction") {
    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes kAccountHistoryKey1{*silkworm::from_hex("a85b4c37cd8f447848d49851a1bb06d10d410c1300000000000fa0a5")};
    static Bytes kAccountHistoryValue1{*silkworm::from_hex("0100000000000000000000003a300000010000000f00000010000000a5a0")};

    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes kAccountHistoryKey2{*silkworm::from_hex("000000000000000000000000000000000000000000000000000fa0a5")};
    static Bytes kAccountHistoryValue2{*silkworm::from_hex(
        "0100000000000000000000003b301800000001000000000002000100040007000600030008000200090000000e0011000f00060011000f"
        "00130003001a0000001c0003001d0000001e0000001f00370020001d002100270222006b00230019002400320025004d00260004002700"
        "04002a000f002b002700d0000000d2000000d6000000e6000000ee000000f4000000f60000001a01000028010000480100005001000052"
        "0100005a0100005c0100005e010000ce0100000a02000000050000d80500000c060000720600000e070000180700002207000042070000"
        "0000d03cd13cd1b6d3b617b718b719b72ab72cb774fa4611c695c795c8957184728474842d12377d4c7d547d767e848053819c81dc81d9"
        "8fee8f059022902f9035903c903f904a9091902eb0fee1ffe101e202e203e205e2e6b1e8b1e9b1eab1edb1eeb1f0b1f1b1f2b1f3b1f5b1"
        "f6b1f7b1f9b1fab1fcb1de62e562e662f2625209b453ba53c153d65304ebb1007f4b8a4b314c9b4c685dc25dcc5df05d045e0c5e315e51"
        "5eb55e0f5f105f2d5fac890f9031907f907e9f0ca0f1a0f6a0faa009a120a126a1f3a1f5a1b1a2b3a21ca41fa425a445a456a458a443a5"
        "95a698a68ad190d1a1e249e577e570e6c3e936f940f921fe28fe2dfe27ff39ff83ff25123612371230439f434d598c593d6c676c996ca0"
        "6cc16cf26c337114826183e386f59729983b9870f284f2a2f283f3a1f3b7f3faf702f84cfa53fabd00d4070000d8070000dd0700000c08"
        "0000730800007f080000c20c00003b1e00003f1e0000671e00006a1e0000ea200000fd200100f8230000ac240000333600008d3600009d"
        "370000673a00000c3b00000b520000105200004d540200c2690000ce690100eb690100ee690000176a0400f9770000d4780000de780000"
        "e478000076790000de790100e1790200007a0100037a0200297a04005b7c0a00677c04006d7c00006f7c0600777c0000797c0600817c00"
        "00837c06008b7c00008d7c0600957c0000977c06009f7c0400a57c0200a97c0000ab7c0500b37c0700bd7c0000bf7c0400c57c0300eb7c"
        "0000f97c0100017d0000057d00000d7d00001c7d0300217d08002b7d00002d7d0600357d0000377d06003f7d0000417d0500497d070053"
        "7d0400597d02005d7d0000607d0500677d0000697d0800737d08007e7d0500857d0000877d0300ba7d0000bd7d0000cc7d0000d47d0000"
        "118e0000978e0000aa8e0000128f0300178f0000198f0700238f0300288f0100408f0100438f06004b8f0400518f08005b8f01005e8f08"
        "00698f00006b8f01006e8f0300748f07007d8f0000808f0300858f0000878f03008c8f0500948f020024900100279001002a9000002c90"
        "020031900000349002003a9002003f9001004290000045900300759000001c91000013a8000023a8000043a8000055aa0000adab0100ca"
        "bd0000b9c20000d9c20000e2c20000f8c2000031d100004ed1000051d1000062d1040068d1070071d109007cd1050084d105008bd10800"
        "95d1000097d106009fd10000a1d10100a4d10300abd10100aed10300b3d10000b5d10000b7d10400bdd10000bfd10200c3d10200c7d100"
        "00cad10200ced10600f6d100007bd20000afd2000038d402006cd4000086d402008ad401008dd400008fd40100c6d5000099d60600a1d6"
        "0400a7d60000a9d60000acd60000aed60100c7d60000d4d60500dbd60200f2d60100f5d60200fad6020010d7010013d7030019d700001b"
        "d701001ed7050025d704002bd7080035d70600a1d80000bad80000701777178b1793179b17ca17db1708181a1829183a183c183d183f18"
        "7a1a811a941a9b1a2f1b371b3a1b514451475d4763477047f147f84701480748114818481c482f483d4843484b48ec59d45a6c5b0f5dca"
        "716f72707271721ba320a37fa585a5c6b6f9b6fbb604b752b899b8b8b8e6b83eb98fb990b991b9bfbac7ba33ca47ca8ecb93cb58cc5fcc"
        "f7cd6ed3c9d6ccd6d5d6a5e4b5e4d6e46fe58be596e597e598e599e59be59ce59ee59fe5a0e5a1e5aae5ace5b4e5b5e5b6e5bbe5bce5bd"
        "e5c0e5c7e5c8e5ece5ede5eee5fae6ffe65cf6e3f7b4f9160e89108a109310aa100d118412ad5681669a669c66f86646675d679f67e067"
        "1c68d86aa26dba6dba81c881b0820298219a40edb809cb09d909b60ad10ac00b3b8f618f958fbc90fba420a53ba5d5baedba07bb40bbb2"
        "bbe2bb02bcd0bef0bf8bc08ec02ace40ce41ce38cfd8d181d4a1d4a3d4dce45be55ee567e572e578e590e59be5a1e5c0e5b8e6dbe693e8"
        "9ee8fbe925ea53eaf6ecd7eea02ab42ae82afa2a042b222bb33db43db63dd13dd23dd53dd83dd93dda3dff3e003f2b3f2c3f2e3f423f43"
        "3f443f4d3f4e3f1c4034402841b741d641e34114424f422d447944a444a944c444c844bd5537563e5644564f567a565b572458a669dd6b"
        "1071127129716c719c71d171ed7115725d74a982ad82ce82d182d68277c47dc40bc53ac767c78cc7bcc71cc823c828c82dc892caa2caa3"
        "cbbdcb39783e8391b992b93dffbb05c205728f928fb6c7b44a365b3f5b08b1f2c41bc52bc57dc592cafbca39cd79cd96f15af221f338f3"
        "c434a94baa4ba84d424e1252125af45e625f645f6e5f556357637a633e64cf64fb66fc66fd66fe66ff6601670267036704670567066708"
        "6709670a67a575f87a4b7b537b157dec7f938d948d958d968d")};

    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes kAccountHistoryKey3{*silkworm::from_hex("daae090d53f9ed9e2e1fd25258c01bac4dd6d1c500000000000fa0a5")};
    static Bytes kAccountHistoryValue3{*silkworm::from_hex(
        "0100000000000000000000003a300000020000000e0004000f0031001800000022000000eca7f4a7d3a9dea9dfa9fd1b191c301cb91cbe"
        "1cf21cfc1c0f1d141d261d801d911da61d00440e4a485f4f5f427b537baf7bb17bb57bb97bbf7bc57bc97bd87bda7be17be47be97bfa7b"
        "fe7b017c267c297c2c7c367c3a9d3b9d3d9d429d47a071a0a5a0aea0b4a0b8a0c3a0c9a0")};

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey1{*silkworm::from_hex("00000000000fa0a5")};
    static Bytes kAccountChangeSetSubkey1{*silkworm::from_hex("a85b4c37cd8f447848d49851a1bb06d10d410c13")};
    static Bytes kAccountChangeSetValue1{*silkworm::from_hex("")};

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey2{*silkworm::from_hex("00000000000fb02e")};
    static Bytes kAccountChangeSetSubkey2{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes kAccountChangeSetValue2{*silkworm::from_hex("0208028ded68c33d1401")};

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet
    static Bytes kAccountChangeSetKey3{*silkworm::from_hex("00000000000fa0a5")};
    static Bytes kAccountChangeSetSubkey3{*silkworm::from_hex("daae090d53f9ed9e2e1fd25258c01bac4dd6d1c5")};
    static Bytes kAccountChangeSetValue3{*silkworm::from_hex("030127080334e1d62a9e3440")};

    auto& tx = transaction;
    EXPECT_CALL(transaction, create_state(_, _, _)).Times(2).WillRepeatedly(Invoke([&tx](auto& ioc, const auto& storage, auto block_number) -> std::shared_ptr<State> {
        return std::make_shared<db::state::RemoteState>(ioc, tx, storage, block_number);
    }));

    EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            SILK_DEBUG << "EXPECT_CALL::get_one "
                       << " table: " << db::table::kCanonicalHashesName
                       << " key: " << silkworm::to_hex(kZeroKey)
                       << " value: " << silkworm::to_hex(kZeroHeader);
            co_return kZeroHeader;
        }));
    EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kConfigName
                       << " key: " << silkworm::to_hex(kConfigKey)
                       << " value: " << silkworm::to_hex(kConfigValue);
            co_return kConfigValue;
        }));

    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey1)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue1);
            co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
        }));
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey2)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue2);
            co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
        }));
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey3)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue3);
            co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1},
                               silkworm::ByteView{kAccountChangeSetSubkey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey1)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey1)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue1);
            co_return kAccountChangeSetValue1;
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2},
                               silkworm::ByteView{kAccountChangeSetSubkey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey2)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey2)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue2);
            co_return kAccountChangeSetValue2;
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey3},
                               silkworm::ByteView{kAccountChangeSetSubkey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey3)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey3)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue3);
            co_return kAccountChangeSetValue3;
        }));

    BlockNum block_number = 1'024'165;  // 0xFA0A5

    silkworm::BlockWithHash block_with_hash;
    block_with_hash.block.header.number = block_number;
    block_with_hash.hash = 0x527198f474c1f1f1d01129d3a17ecc17895d85884a31b05ef0ecd480faee1592_bytes32;

    rpc::Transaction txn;
    txn.set_sender(0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5_address);
    txn.nonce = 27;
    txn.value = 0;
    txn.data = *silkworm::from_hex(
        "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004"
        "361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080"
        "fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060"
        "008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c"
        "60af2c64736f6c634300050a0032");
    txn.max_priority_fee_per_gas = 0x3b9aca00;
    txn.max_fee_per_gas = 0x3b9aca00;
    txn.gas_limit = 0x47b760;
    txn.type = TransactionType::kLegacy;
    txn.block_hash = block_with_hash.hash;
    txn.block_number = block_number;
    txn.transaction_index = 0;

    block_with_hash.block.transactions.push_back(txn);

    SECTION("Call: only vmTrace") {
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        TraceConfig config{.vm_trace = true, .trace = false, .state_diff = false};
        const auto result = spawn_and_wait(executor.trace_transaction(block_with_hash.block, txn, config));

        CHECK(nlohmann::json(result) == R"({
            "output": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "stateDiff": null,
            "trace": [],
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "vmTrace": {
                "code": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                "ops": [
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x80"
                    ],
                    "store": null,
                    "used": 4643449
                    },
                    "idx": "0-0",
                    "op": "PUSH1",
                    "pc": 0,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x40"
                    ],
                    "store": null,
                    "used": 4643446
                    },
                    "idx": "0-1",
                    "op": "PUSH1",
                    "pc": 2,
                    "sub": null
                },
                {
                    "cost": 12,
                    "ex": {
                    "mem": {
                        "data": "0x0000000000000000000000000000000000000000000000000000000000000080",
                        "off": 64
                    },
                    "push": [],
                    "store": null,
                    "used": 4643434
                    },
                    "idx": "0-2",
                    "op": "MSTORE",
                    "pc": 4,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4643431
                    },
                    "idx": "0-3",
                    "op": "PUSH1",
                    "pc": 5,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0",
                        "0x0"
                    ],
                    "store": null,
                    "used": 4643428
                    },
                    "idx": "0-4",
                    "op": "DUP1",
                    "pc": 7,
                    "sub": null
                },
                {
                    "cost": 2200,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": {
                        "key": "0x0",
                        "val": "0x0"
                    },
                    "used": 4641228
                    },
                    "idx": "0-5",
                    "op": "SSTORE",
                    "pc": 8,
                    "sub": null
                },
                {
                    "cost": 2,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641226
                    },
                    "idx": "0-6",
                    "op": "CALLVALUE",
                    "pc": 9,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0",
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641223
                    },
                    "idx": "0-7",
                    "op": "DUP1",
                    "pc": 10,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x1"
                    ],
                    "store": null,
                    "used": 4641220
                    },
                    "idx": "0-8",
                    "op": "ISZERO",
                    "pc": 11,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x14"
                    ],
                    "store": null,
                    "used": 4641217
                    },
                    "idx": "0-9",
                    "op": "PUSH2",
                    "pc": 12,
                    "sub": null
                },
                {
                    "cost": 10,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641207
                    },
                    "idx": "0-10",
                    "op": "JUMPI",
                    "pc": 15,
                    "sub": null
                },
                {
                    "cost": 1,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641206
                    },
                    "idx": "0-11",
                    "op": "JUMPDEST",
                    "pc": 20,
                    "sub": null
                },
                {
                    "cost": 2,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641204
                    },
                    "idx": "0-12",
                    "op": "POP",
                    "pc": 21,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0xc6"
                    ],
                    "store": null,
                    "used": 4641201
                    },
                    "idx": "0-13",
                    "op": "PUSH1",
                    "pc": 22,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0xc6",
                        "0xc6"
                    ],
                    "store": null,
                    "used": 4641198
                    },
                    "idx": "0-14",
                    "op": "DUP1",
                    "pc": 24,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x23"
                    ],
                    "store": null,
                    "used": 4641195
                    },
                    "idx": "0-15",
                    "op": "PUSH2",
                    "pc": 25,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641192
                    },
                    "idx": "0-16",
                    "op": "PUSH1",
                    "pc": 28,
                    "sub": null
                },
                {
                    "cost": 36,
                    "ex": {
                    "mem": {
                        "data": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                        "off": 0
                    },
                    "push": [],
                    "store": null,
                    "used": 4641156
                    },
                    "idx": "0-17",
                    "op": "CODECOPY",
                    "pc": 30,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641153
                    },
                    "idx": "0-18",
                    "op": "PUSH1",
                    "pc": 31,
                    "sub": null
                },
                {
                    "cost": 0,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641153
                    },
                    "idx": "0-19",
                    "op": "RETURN",
                    "pc": 33,
                    "sub": null
                }
                ]
            }
        })"_json);
    }

    SECTION("Call: only trace") {
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        TraceConfig config{.vm_trace = false, .trace = true, .state_diff = false};
        const auto result = spawn_and_wait(executor.trace_transaction(block_with_hash.block, txn, config));

        CHECK(nlohmann::json(result) == R"({
            "output": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "stateDiff": null,
            "trace": [
                {
                "action": {
                    "from": "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5",
                    "gas": "0x46da7c",
                    "init": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                    "value": "0x0"
                },
                "result": {
                    "address": "0xa85b4c37cd8f447848d49851a1bb06d10d410c13",
                    "code": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                    "gasUsed": "0xa3ab"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "create"
                }
            ],
            "vmTrace": null
        })"_json);
    }
    SECTION("Call: only stateDiff") {
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        TraceConfig config{.vm_trace = false, .trace = false, .state_diff = true};
        const auto result = spawn_and_wait(executor.trace_transaction(block_with_hash.block, txn, config));

        CHECK(nlohmann::json(result) == R"({
            "output": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                "balance": {
                    "*": {
                    "from": "0x28ded68c33d1401",
                    "to": "0x28e46f23db3ea01"
                    }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
                },
                "0xa85b4c37cd8f447848d49851a1bb06d10d410c13": {
                "balance": {
                    "+": "0x0"
                },
                "code": {
                    "+": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032"
                },
                "nonce": {
                    "+": "0x1"
                },
                "storage": {}
                },
                "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5": {
                "balance": {
                    "*": {
                    "from": "0x334e1d62a9e3440",
                    "to": "0x334884cb0275e40"
                    }
                },
                "code": "=",
                "nonce": {
                    "*": {
                    "from": "0x27",
                    "to": "0x28"
                    }
                },
                "storage": {}
                }
            },
            "trace": [],
            "vmTrace": null
        })"_json);
    }
    SECTION("Call: full output") {
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        TraceConfig config{.vm_trace = true, .trace = true, .state_diff = true};
        const auto result = spawn_and_wait(executor.trace_transaction(block_with_hash.block, txn, config));

        CHECK(nlohmann::json(result) == R"({
            "output": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                "balance": {
                    "*": {
                    "from": "0x28ded68c33d1401",
                    "to": "0x28e46f23db3ea01"
                    }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
                },
                "0xa85b4c37cd8f447848d49851a1bb06d10d410c13": {
                "balance": {
                    "+": "0x0"
                },
                "code": {
                    "+": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032"
                },
                "nonce": {
                    "+": "0x1"
                },
                "storage": {}
                },
                "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5": {
                "balance": {
                    "*": {
                    "from": "0x334e1d62a9e3440",
                    "to": "0x334884cb0275e40"
                    }
                },
                "code": "=",
                "nonce": {
                    "*": {
                    "from": "0x27",
                    "to": "0x28"
                    }
                },
                "storage": {}
                }
            },
            "trace": [
                {
                "action": {
                    "from": "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5",
                    "gas": "0x46da7c",
                    "init": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                    "value": "0x0"
                },
                "result": {
                    "address": "0xa85b4c37cd8f447848d49851a1bb06d10d410c13",
                    "code": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                    "gasUsed": "0xa3ab"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "create"
                }
            ],
            "vmTrace": {
                "code": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                "ops": [
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x80"
                    ],
                    "store": null,
                    "used": 4643449
                    },
                    "idx": "0-0",
                    "op": "PUSH1",
                    "pc": 0,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x40"
                    ],
                    "store": null,
                    "used": 4643446
                    },
                    "idx": "0-1",
                    "op": "PUSH1",
                    "pc": 2,
                    "sub": null
                },
                {
                    "cost": 12,
                    "ex": {
                    "mem": {
                        "data": "0x0000000000000000000000000000000000000000000000000000000000000080",
                        "off": 64
                    },
                    "push": [],
                    "store": null,
                    "used": 4643434
                    },
                    "idx": "0-2",
                    "op": "MSTORE",
                    "pc": 4,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4643431
                    },
                    "idx": "0-3",
                    "op": "PUSH1",
                    "pc": 5,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0",
                        "0x0"
                    ],
                    "store": null,
                    "used": 4643428
                    },
                    "idx": "0-4",
                    "op": "DUP1",
                    "pc": 7,
                    "sub": null
                },
                {
                    "cost": 2200,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": {
                        "key": "0x0",
                        "val": "0x0"
                    },
                    "used": 4641228
                    },
                    "idx": "0-5",
                    "op": "SSTORE",
                    "pc": 8,
                    "sub": null
                },
                {
                    "cost": 2,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641226
                    },
                    "idx": "0-6",
                    "op": "CALLVALUE",
                    "pc": 9,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0",
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641223
                    },
                    "idx": "0-7",
                    "op": "DUP1",
                    "pc": 10,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x1"
                    ],
                    "store": null,
                    "used": 4641220
                    },
                    "idx": "0-8",
                    "op": "ISZERO",
                    "pc": 11,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x14"
                    ],
                    "store": null,
                    "used": 4641217
                    },
                    "idx": "0-9",
                    "op": "PUSH2",
                    "pc": 12,
                    "sub": null
                },
                {
                    "cost": 10,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641207
                    },
                    "idx": "0-10",
                    "op": "JUMPI",
                    "pc": 15,
                    "sub": null
                },
                {
                    "cost": 1,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641206
                    },
                    "idx": "0-11",
                    "op": "JUMPDEST",
                    "pc": 20,
                    "sub": null
                },
                {
                    "cost": 2,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641204
                    },
                    "idx": "0-12",
                    "op": "POP",
                    "pc": 21,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0xc6"
                    ],
                    "store": null,
                    "used": 4641201
                    },
                    "idx": "0-13",
                    "op": "PUSH1",
                    "pc": 22,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0xc6",
                        "0xc6"
                    ],
                    "store": null,
                    "used": 4641198
                    },
                    "idx": "0-14",
                    "op": "DUP1",
                    "pc": 24,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x23"
                    ],
                    "store": null,
                    "used": 4641195
                    },
                    "idx": "0-15",
                    "op": "PUSH2",
                    "pc": 25,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641192
                    },
                    "idx": "0-16",
                    "op": "PUSH1",
                    "pc": 28,
                    "sub": null
                },
                {
                    "cost": 36,
                    "ex": {
                    "mem": {
                        "data": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                        "off": 0
                    },
                    "push": [],
                    "store": null,
                    "used": 4641156
                    },
                    "idx": "0-17",
                    "op": "CODECOPY",
                    "pc": 30,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641153
                    },
                    "idx": "0-18",
                    "op": "PUSH1",
                    "pc": 31,
                    "sub": null
                },
                {
                    "cost": 0,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641153
                    },
                    "idx": "0-19",
                    "op": "RETURN",
                    "pc": 33,
                    "sub": null
                }
                ]
            }
          })"_json);
    }
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_transaction") {
    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes kAccountHistoryKey1{*silkworm::from_hex("a85b4c37cd8f447848d49851a1bb06d10d410c1300000000000fa0a5")};
    static Bytes kAccountHistoryValue1{*silkworm::from_hex("0100000000000000000000003a300000010000000f00000010000000a5a0")};

    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes kAccountHistoryKey2{*silkworm::from_hex("000000000000000000000000000000000000000000000000000fa0a5")};
    static Bytes kAccountHistoryValue2{*silkworm::from_hex(
        "0100000000000000000000003b301800000001000000000002000100040007000600030008000200090000000e0011000f00060011000f"
        "00130003001a0000001c0003001d0000001e0000001f00370020001d002100270222006b00230019002400320025004d00260004002700"
        "04002a000f002b002700d0000000d2000000d6000000e6000000ee000000f4000000f60000001a01000028010000480100005001000052"
        "0100005a0100005c0100005e010000ce0100000a02000000050000d80500000c060000720600000e070000180700002207000042070000"
        "0000d03cd13cd1b6d3b617b718b719b72ab72cb774fa4611c695c795c8957184728474842d12377d4c7d547d767e848053819c81dc81d9"
        "8fee8f059022902f9035903c903f904a9091902eb0fee1ffe101e202e203e205e2e6b1e8b1e9b1eab1edb1eeb1f0b1f1b1f2b1f3b1f5b1"
        "f6b1f7b1f9b1fab1fcb1de62e562e662f2625209b453ba53c153d65304ebb1007f4b8a4b314c9b4c685dc25dcc5df05d045e0c5e315e51"
        "5eb55e0f5f105f2d5fac890f9031907f907e9f0ca0f1a0f6a0faa009a120a126a1f3a1f5a1b1a2b3a21ca41fa425a445a456a458a443a5"
        "95a698a68ad190d1a1e249e577e570e6c3e936f940f921fe28fe2dfe27ff39ff83ff25123612371230439f434d598c593d6c676c996ca0"
        "6cc16cf26c337114826183e386f59729983b9870f284f2a2f283f3a1f3b7f3faf702f84cfa53fabd00d4070000d8070000dd0700000c08"
        "0000730800007f080000c20c00003b1e00003f1e0000671e00006a1e0000ea200000fd200100f8230000ac240000333600008d3600009d"
        "370000673a00000c3b00000b520000105200004d540200c2690000ce690100eb690100ee690000176a0400f9770000d4780000de780000"
        "e478000076790000de790100e1790200007a0100037a0200297a04005b7c0a00677c04006d7c00006f7c0600777c0000797c0600817c00"
        "00837c06008b7c00008d7c0600957c0000977c06009f7c0400a57c0200a97c0000ab7c0500b37c0700bd7c0000bf7c0400c57c0300eb7c"
        "0000f97c0100017d0000057d00000d7d00001c7d0300217d08002b7d00002d7d0600357d0000377d06003f7d0000417d0500497d070053"
        "7d0400597d02005d7d0000607d0500677d0000697d0800737d08007e7d0500857d0000877d0300ba7d0000bd7d0000cc7d0000d47d0000"
        "118e0000978e0000aa8e0000128f0300178f0000198f0700238f0300288f0100408f0100438f06004b8f0400518f08005b8f01005e8f08"
        "00698f00006b8f01006e8f0300748f07007d8f0000808f0300858f0000878f03008c8f0500948f020024900100279001002a9000002c90"
        "020031900000349002003a9002003f9001004290000045900300759000001c91000013a8000023a8000043a8000055aa0000adab0100ca"
        "bd0000b9c20000d9c20000e2c20000f8c2000031d100004ed1000051d1000062d1040068d1070071d109007cd1050084d105008bd10800"
        "95d1000097d106009fd10000a1d10100a4d10300abd10100aed10300b3d10000b5d10000b7d10400bdd10000bfd10200c3d10200c7d100"
        "00cad10200ced10600f6d100007bd20000afd2000038d402006cd4000086d402008ad401008dd400008fd40100c6d5000099d60600a1d6"
        "0400a7d60000a9d60000acd60000aed60100c7d60000d4d60500dbd60200f2d60100f5d60200fad6020010d7010013d7030019d700001b"
        "d701001ed7050025d704002bd7080035d70600a1d80000bad80000701777178b1793179b17ca17db1708181a1829183a183c183d183f18"
        "7a1a811a941a9b1a2f1b371b3a1b514451475d4763477047f147f84701480748114818481c482f483d4843484b48ec59d45a6c5b0f5dca"
        "716f72707271721ba320a37fa585a5c6b6f9b6fbb604b752b899b8b8b8e6b83eb98fb990b991b9bfbac7ba33ca47ca8ecb93cb58cc5fcc"
        "f7cd6ed3c9d6ccd6d5d6a5e4b5e4d6e46fe58be596e597e598e599e59be59ce59ee59fe5a0e5a1e5aae5ace5b4e5b5e5b6e5bbe5bce5bd"
        "e5c0e5c7e5c8e5ece5ede5eee5fae6ffe65cf6e3f7b4f9160e89108a109310aa100d118412ad5681669a669c66f86646675d679f67e067"
        "1c68d86aa26dba6dba81c881b0820298219a40edb809cb09d909b60ad10ac00b3b8f618f958fbc90fba420a53ba5d5baedba07bb40bbb2"
        "bbe2bb02bcd0bef0bf8bc08ec02ace40ce41ce38cfd8d181d4a1d4a3d4dce45be55ee567e572e578e590e59be5a1e5c0e5b8e6dbe693e8"
        "9ee8fbe925ea53eaf6ecd7eea02ab42ae82afa2a042b222bb33db43db63dd13dd23dd53dd83dd93dda3dff3e003f2b3f2c3f2e3f423f43"
        "3f443f4d3f4e3f1c4034402841b741d641e34114424f422d447944a444a944c444c844bd5537563e5644564f567a565b572458a669dd6b"
        "1071127129716c719c71d171ed7115725d74a982ad82ce82d182d68277c47dc40bc53ac767c78cc7bcc71cc823c828c82dc892caa2caa3"
        "cbbdcb39783e8391b992b93dffbb05c205728f928fb6c7b44a365b3f5b08b1f2c41bc52bc57dc592cafbca39cd79cd96f15af221f338f3"
        "c434a94baa4ba84d424e1252125af45e625f645f6e5f556357637a633e64cf64fb66fc66fd66fe66ff6601670267036704670567066708"
        "6709670a67a575f87a4b7b537b157dec7f938d948d958d968d")};

    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes kAccountHistoryKey3{*silkworm::from_hex("daae090d53f9ed9e2e1fd25258c01bac4dd6d1c500000000000fa0a5")};
    static Bytes kAccountHistoryValue3{*silkworm::from_hex(
        "0100000000000000000000003a300000020000000e0004000f0031001800000022000000eca7f4a7d3a9dea9dfa9fd1b191c301cb91cbe"
        "1cf21cfc1c0f1d141d261d801d911da61d00440e4a485f4f5f427b537baf7bb17bb57bb97bbf7bc57bc97bd87bda7be17be47be97bfa7b"
        "fe7b017c267c297c2c7c367c3a9d3b9d3d9d429d47a071a0a5a0aea0b4a0b8a0c3a0c9a0")};

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey1{*silkworm::from_hex("00000000000fa0a5")};
    static Bytes kAccountChangeSetSubkey1{*silkworm::from_hex("a85b4c37cd8f447848d49851a1bb06d10d410c13")};
    static Bytes kAccountChangeSetValue1{*silkworm::from_hex("")};

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey2{*silkworm::from_hex("00000000000fb02e")};
    static Bytes kAccountChangeSetSubkey2{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes kAccountChangeSetValue2{*silkworm::from_hex("0208028ded68c33d1401")};

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet
    static Bytes kAccountChangeSetKey3{*silkworm::from_hex("00000000000fa0a5")};
    static Bytes kAccountChangeSetSubkey3{*silkworm::from_hex("daae090d53f9ed9e2e1fd25258c01bac4dd6d1c5")};
    static Bytes kAccountChangeSetValue3{*silkworm::from_hex("030127080334e1d62a9e3440")};

    auto& tx = transaction;
    EXPECT_CALL(transaction, create_state(_, _, _)).Times(2).WillRepeatedly(Invoke([&tx](auto& ioc, const auto& storage, auto block_number) -> std::shared_ptr<State> {
        return std::make_shared<db::state::RemoteState>(ioc, tx, storage, block_number);
    }));

    EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            SILK_DEBUG << "EXPECT_CALL::get_one "
                       << " table: " << db::table::kCanonicalHashesName
                       << " key: " << silkworm::to_hex(kZeroKey)
                       << " value: " << silkworm::to_hex(kZeroHeader);
            co_return kZeroHeader;
        }));
    EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kConfigName
                       << " key: " << silkworm::to_hex(kConfigKey)
                       << " value: " << silkworm::to_hex(kConfigValue);
            co_return kConfigValue;
        }));

    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey1)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue1);
            co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
        }));
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey2)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue2);
            co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
        }));
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            SILK_DEBUG << "EXPECT_CALL::get "
                       << " table: " << db::table::kAccountHistoryName
                       << " key: " << silkworm::to_hex(kAccountHistoryKey3)
                       << " value: " << silkworm::to_hex(kAccountHistoryValue3);
            co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1},
                               silkworm::ByteView{kAccountChangeSetSubkey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey1)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey1)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue1);
            co_return kAccountChangeSetValue1;
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2},
                               silkworm::ByteView{kAccountChangeSetSubkey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey2)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey2)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue2);
            co_return kAccountChangeSetValue2;
        }));
    EXPECT_CALL(transaction,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey3},
                               silkworm::ByteView{kAccountChangeSetSubkey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            SILK_DEBUG << "EXPECT_CALL::get_both_range "
                       << " table: " << db::table::kAccountChangeSetName
                       << " key: " << silkworm::to_hex(kAccountChangeSetKey3)
                       << " subkey: " << silkworm::to_hex(kAccountChangeSetSubkey3)
                       << " value: " << silkworm::to_hex(kAccountChangeSetValue3);
            co_return kAccountChangeSetValue3;
        }));

    BlockNum block_number = 1'024'165;  // 0xFA0A5

    silkworm::BlockWithHash block_with_hash;
    block_with_hash.block.header.number = block_number;
    block_with_hash.hash = 0x527198f474c1f1f1d01129d3a17ecc17895d85884a31b05ef0ecd480faee1592_bytes32;

    rpc::Transaction txn;
    txn.set_sender(0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5_address);
    txn.nonce = 27;
    txn.value = 0;
    txn.data = *silkworm::from_hex(
        "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004"
        "361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080"
        "fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060"
        "008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c"
        "60af2c64736f6c634300050a0032");
    txn.max_priority_fee_per_gas = 0x3b9aca00;
    txn.max_fee_per_gas = 0x3b9aca00;
    txn.gas_limit = 0x47b760;
    txn.type = TransactionType::kLegacy;
    txn.block_hash = block_with_hash.hash;
    txn.block_number = block_number;
    txn.transaction_index = 0;

    block_with_hash.block.transactions.push_back(txn);

    TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
    const auto result = spawn_and_wait(executor.trace_transaction(block_with_hash, txn, true));

    CHECK(nlohmann::json(result) == R"([
        {
            "action": {
            "from": "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5",
            "gas": "0x46da7c",
            "init": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "value": "0x0"
            },
            "blockHash": "0x527198f474c1f1f1d01129d3a17ecc17895d85884a31b05ef0ecd480faee1592",
            "blockNumber": 1024165,
            "result": {
            "address": "0xa85b4c37cd8f447848d49851a1bb06d10d410c13",
            "code": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "gasUsed": "0xa3ab"
            },
            "subtraces": 0,
            "traceAddress": [],
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "transactionPosition": 0,
            "type": "create"
        }
    ])"_json);
}

#ifdef TEST_DELETED
TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_filter") {
    StringWriter string_writer(4096);
    json::Stream stream(string_writer);

    auto& tx = transaction;
    EXPECT_CALL(transaction, create_state(_, _, _)).Times(2).WillRepeatedly(Invoke([&tx](auto& ioc, const auto& storage, auto block_number) -> std::shared_ptr<State> {
        return std::make_shared<db::state::RemoteState>(ioc, tx, storage, block_number);
    }));

    EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kZeroHeader;
        }));

    // TransactionDatabase::get_one: TABLE CanonicalHeader
    static Bytes kCanonicalHeaderKey1{*silkworm::from_hex("00000000006ddd02")};
    static Bytes kCanonicalHeaderValue1{*silkworm::from_hex("a87009e08f9af73efe86d702561afcf98f277a8acec60b97869969e367c12d66")};
    EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kCanonicalHeaderKey1}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kCanonicalHeaderValue1;
        }));

    // TransactionDatabase::get_one: TABLE CanonicalHeader > 1
    static Bytes kCanonicalHeaderKey2{*silkworm::from_hex("00000000006ddd00")};
    static Bytes kCanonicalHeaderValue2{*silkworm::from_hex("bf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a")};
    EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kCanonicalHeaderKey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kCanonicalHeaderValue2;
        }));

    //  TransactionDatabase::get_one: TABLE CanonicalHeader
    static Bytes kCanonicalHeaderKey4{*silkworm::from_hex("00000000006ddd03")};
    static Bytes kCanonicalHeaderValue4{*silkworm::from_hex("a316f156582fb5fba2166910becdb6342965a801fa473e18cd6a0c06143cac1a")};
    EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kCanonicalHeaderKey4}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kCanonicalHeaderValue4;
        }));

    // TransactionDatabase::get: TABLE Header
    static Bytes kHeaderKey1{*silkworm::from_hex("00000000006ddd02a87009e08f9af73efe86d702561afcf98f277a8acec60b97869969e367c12d66")};
    static Bytes kHeaderValue1{*silkworm::from_hex(
        "f9025da037a3632c35befe7acc0504b6bd0bc0d56f8d786d8482cd2053389a6b2ceff7daa01dcc4de8dec75d7aab85b567b6ccd41ad312"
        "451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a01661c7e4b4e67b091aa557e4eae760549e0089"
        "9c5c83525a0536253d7720b0a7a04ffc3015454dec2d4092214e44fff75c840808a94a372a3e478123b815fda632a0056b23fbba480696"
        "b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2b9010000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000001836ddd028401c9c3808252088462ca3c56b861d883010a15846765746888676f312e31382e33856c696e75780000"
        "00000000004c236ff3870624cd2799e94f7b161ff5f621afad28f7e305e0a68373194b7646151ee25c25ef1bba87ab6f639c0f16d418b7"
        "11a46fe57e5f03f6b890ab311a5a01a0000000000000000000000000000000000000000000000000000000000000000088000000000000"
        "000007")};
    EXPECT_CALL(transaction, get_one(db::table::kHeadersName, silkworm::ByteView{kHeaderKey1}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kHeaderValue1;
        }));

    // TransactionDatabase::get: TABLE Header
    static Bytes kHeaderKey3{*silkworm::from_hex("00000000006ddd03a316f156582fb5fba2166910becdb6342965a801fa473e18cd6a0c06143cac1a")};
    static Bytes kHeaderValue3{*silkworm::from_hex(
        "f9025ea0a87009e08f9af73efe86d702561afcf98f277a8acec60b97869969e367c12d66a01dcc4de8dec75d7aab85b567b6ccd41ad312"
        "451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a000636fe848d9d0dd8d3fe77deef0286329b01f"
        "4e971501d1dc481365deea77bfa0edf245e6b99fa3effd929d49b1015565a97858ca8bec78a144d3734368d8b135a037a2efb1bda0ba83"
        "3792a034210991a591949131e34700436c335ddf3c45113db9010000000000000000000000000000000000000000000000000000000100"
        "00000000000000000040000000000000000000000000000000000000001000000000400000000000000000000000000800000000000000"
        "00000000000000000000000000000000000200000000000000000008000000000000000000000000100000000000000000000000004000"
        "40000000000010800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000200000008000000000001000000000400000000000000000000002100000000000000000000400000000000000000000000000000"
        "000000020000008001836ddd038401c9c3808315abb08462ca3c65b86100000000000000000000000051396620476f65726c6920417574"
        "686f72697479a59ef12661bd272752d7a69ef2e2b47af6909b840d709fa222d059536ab7469d411764f1fe49f4b7a3f5782659f74d27f4"
        "dcce1506a9f0f26ccb48a806d92f2e01a00000000000000000000000000000000000000000000000000000000000000000880000000000"
        "00000007")};
    EXPECT_CALL(transaction, get_one(db::table::kHeadersName, silkworm::ByteView{kHeaderKey3}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kHeaderValue3;
        }));

    // TransactionDatabase::get: TABLE BlockBody
    static Bytes kBlockBodyKey1{*silkworm::from_hex("00000000006ddd02a87009e08f9af73efe86d702561afcf98f277a8acec60b97869969e367c12d66")};
    static Bytes kBlockBodyValue1{*silkworm::from_hex("c78405c62e6603c0")};
    EXPECT_CALL(transaction, get_one(db::table::kBlockBodiesName, silkworm::ByteView{kBlockBodyKey1}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kBlockBodyValue1;
        }));

    // TransactionDatabase::get: TABLE BlockBody
    static Bytes kBlockBodyKey3{*silkworm::from_hex("00000000006ddd03a316f156582fb5fba2166910becdb6342965a801fa473e18cd6a0c06143cac1a")};
    static Bytes kBlockBodyValue3{*silkworm::from_hex("c78405c62e6904c0")};
    EXPECT_CALL(transaction, get_one(db::table::kBlockBodiesName, silkworm::ByteView{kBlockBodyKey3}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kBlockBodyValue3;
        }));

    // TransactionDatabase::walk: TABLE BlockTransaction
    static Bytes kBlockTransactionKey1{*silkworm::from_hex("0000000005c62e67")};
    static uint32_t kBlockTransactionFixedBits1{0};
    EXPECT_CALL(transaction, walk(db::table::kBlockTransactionsName, silkworm::ByteView{kBlockTransactionKey1}, kBlockTransactionFixedBits1, _))
        .WillOnce(InvokeWithoutArgs([]() -> Task<void> {
            co_return;
        }));

    // TransactionDatabase::walk: TABLE BlockTransaction
    static Bytes kBlockTransactionKey2{*silkworm::from_hex("0000000005c62e6a")};
    static uint32_t kBlockTransactionFixedBits2{0};
    EXPECT_CALL(transaction, walk(db::table::kBlockTransactionsName, silkworm::ByteView{kBlockTransactionKey2}, kBlockTransactionFixedBits2, _))
        .WillOnce(InvokeWithoutArgs([]() -> Task<void> {
            co_return;
        }));

    EXPECT_CALL(transaction, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kConfigValue;
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey1{*silkworm::from_hex("2031832e54a2200bf678286f560f49a950db2ad500000000006ddd02")};
    static Bytes kAccountHistoryValue1{*silkworm::from_hex(
        "0100000000000000000000003a300000020000006d005e036e005d0018000000d6060000a6bbb3bbc5bbd1bbe5bbf3bb04bc10bc18bc29"
        "bc32bc40bc4ebc56bc60bc70bc86bc8fbca5bcc4bcd3bcf3bc0abd17bd22bd2ebd37bd49bd58bd71bd7cbd94bdabbdc2bdd2bdddbdf0bd"
        "f9bd17be26be33be45be56be6fbe85be8dbea1beabbec1bedabee5bef9be17bf26bf3bbf4fbf6ebf82bfadbfc3bfe3bff9bf24c04cc069"
        "c097c0a9c0dbc0f8c00dc13bc156c172c18ac19fc1c2c1ecc10cc225c239c260c27fc2b4c2f1c227c33bc365c38bc3d0c3f5c325c464c4"
        "9fc4c6c416c542c57ec59dc5cfc5f8c51cc634c65ac673c686c6b5c6d0c6edc604c720c73ec756c787c79fc7b6c7dec702c826c856c871"
        "c88ec8a0c8b4c8ccc8e8c8fcc810c927c92ac938c954c962c977c993c9b8c9cbc9e1c9f8c910ca17ca1dca34ca49ca5dca6dca81ca94ca"
        "b0cac5cad2cae6caf5ca05cb11cb22cb33cb3ecb51cb68cb80cb9dcbb7cbc9cbdccbeecb08cc15cc27cc33cc4fcc59cc76cc91cc9bcca1"
        "ccafcccfcce3ccefccfdcc0ccd16cd1fcd2acd2ecd36cd40cd48cd51cd54cd5ecd6ecd7bcd94cd98cda1cdaecdd1cddbcde1cdf2cdffcd"
        "10ce18ce1fce34ce4bce62ce6ece86ce94cea0ceb5cecaced9ceefceface0fcf21cf3ccf44cf4acf56cf62cf6fcf82cf8fcf9acf9fcfb7"
        "cfc8cfd3cfd9cfeccff9cf18d025d03ed054d065d073d07dd095d0a8d0c0d0c7d0d4d0e2d0f6d002d10cd11dd137d140d14ad153d16bd1"
        "7ed192d1a5d1b2d1bad1c8d1dad1e7d1f5d1ffd110d21fd22bd239d246d253d261d26cd275d281d28fd29ed2b9d2c2d2c5d2d3d2ecd2ff"
        "d20fd32bd336d33dd348d355d35fd36fd375d38dd39cd3b5d3cdd3e7d301d415d42ad433d447d459d469d477d483d495d4a9d4bdd4ccd4"
        "edd409d521d54cd593d5c8d5ddd5f8d518d633d645d680d693d6a0d6afd6ccd6e0d608d716d724d731d744d75bd779d783d7a8d7cbd7df"
        "d708d81dd83fd851d887d8b7d8ced80bd959d99bd9d4d919da3eda6bda97dacedafcda40db61db91dbb8dbdedbeddb0bdc20dc49dc59dc"
        "65dc8bdca2dcc0dce3dc02dd28dd40dd5edd7edd98ddc7dde5dd00de17de27de43de7ade85de93dea3deb1decddee1dee7defdde0ddf1e"
        "df32df3edf55df73df8ddf9ddfa9dfbddfcbdfd8dff2df02e010e01be030e051e057e06ae07ae08be0a3e0abe0b6e0cae0d5e0ebe000e1"
        "12e12ee139e147e151e15ee16de17de18ae196e1a7e1b3e1d6e1e3e1f9e108e215e225e242e255e25ee26ee27ae285e290e2a4e2b7e2c0"
        "e2cee2d5e2eae203e31fe32fe341e350e35be371e389e39ce3ade3bbe3cee3eee309e41de43de45ce475e486e495e4ace4c3e4d4e4eae4"
        "fbe410e520e52ce539e543e55ae566e578e58ce59de5b1e5c5e5d8e5ede5fee50fe623e63ae643e64ee660e674e67ae68be6a4e6aae6bb"
        "e6c5e6d2e6d9e6e4e6efe605e71ae739e74fe768e771e77de792e79be7b5e7c3e7dce7ede702e80ce816e81de82fe83ee84be859e86ce8"
        "78e885e88ee897e899e89be8a3e8b0e8bce8cfe8d9e8e3e8eae8f6e8fbe8fde8fee8ffe804e90ae91fe934e948e95be969e982e99ae9ab"
        "e9b8e9d6e9dde9f4e906ea10ea24ea30ea4bea60ea6eea7dea8fea9feaa5eabceac7ead5eadfeaffea19eb21eb26eb32eb41eb4deb50eb"
        "5eeb67eb6feb72eb75eb89eba1ebacebb6ebc9ebe7ebf5eb0bec1bec3fec60ec79ecacecc7ecf3ec09ed17ed24ed3ded5ced79ed93edc4"
        "edf2ed19ee36ee4fee6cee8feec1ee07ef35ef5fef6aef7eefcaef02f05af088f0b8f0e7f00af133f16ff1a3f1bcf1c3f1ccf1cff1d8f1"
        "e0f1e7f1f0f109f222f22cf241f254f263f277f290f29ef2acf2caf2e6f209f327f343f352f366f376f384f389f39af3a7f3b1f3cbf3db"
        "f3e6f3f1f300f40bf42af444f452f464f47df48af4a3f4baf4d3f4e5f403f51af54bf56cf580f593f5a9f5bcf5cef5e7f5f0f506f60ff6"
        "1ff636f648f65af66ff681f68cf694f6a5f6acf6b4f6bcf6c5f6cdf6dff6ecf6f9f60df71ff728f736f748f756f764f771f77cf78bf797"
        "f7a7f7aef7b6f7c2f7cdf7e1f7eef7f9f703f80ff81ff829f836f840f851f85ef865f871f87bf886f890f89cf8aaf8b7f8c1f8d1f8def8"
        "f4f816f923f931f93df947f963f974f98cf9a8f9b4f9cef9def9e6f9fef912fa2cfa3efa5cfa6cfa7cfa8cfa93faabfac0fad2faeefa03"
        "fb10fb25fb32fb59fb6afb7cfb92fb9efbaafbbafbccfbe5fbfffb0afc1efc2efc49fc55fc63fc72fc83fc96fca7fcb6fcc5fcd7fce6fc"
        "f7fc08fd0ffd1afd25fd31fd38fd44fd64fd72fd77fd7cfd84fd8efd9afdacfdb6fdc2fdd5fde2fdf6fdfefd0ffe1dfe29fe35fe3efe48"
        "fe4bfe54fe59fe66fe82fe88fe97feadfeb2fec1fedffef2fefefe01ff06ff1aff34ff48ff56ff5eff78ff86ff90ff9bffadffb2ffb4ff"
        "b9ff7501840193019a01b401d701d801d901da01e501fd0121022c02440261027d028902a002c902f6020d0326033f035f0374039603af"
        "03cb03e603fc0310042e043e045d046b048f04b704d604f40422053e056f059105a205ca0505063e0658068006c706f306120738075c07"
        "8d07b407f207040826084a088d08a808d908ed081d093709540966098f09a709be09cb09e309ed09f209030a0c0a200a310a3e0a460a51"
        "0a680a760a860aa10abc0ae50aed0a0d0b140b1f0b2b0b4c0b")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey2{*silkworm::from_hex("560f0b51eca3f4c6e5873de9091c8f4c200e8ac100000000006ddd02")};
    static Bytes kAccountHistoryValue2{
        *silkworm::from_hex("0100000000000000000000003a300000030000006d000900710000007200000020000000340000003600000086"
                            "55ad5503560b56175621562e5602dd27dd33dd14cca6e5")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey3{*silkworm::from_hex("000000000000000000000000000000000000000000000000006ddd02")};
    static Bytes kAccountHistoryValue3{*silkworm::from_hex(
        "0100000000000000000000003a3000001c00000053001200540054005500010056000100570005005800030059000a005a0005005b0006"
        "005c0001005d00a8005e0009005f000a00600028006100e80062000700630003006400020065000700660011006700190068001d006900"
        "11006a0007006b0022006c0027006d001f006e000e00e80000000e010000b8010000bc010000c0010000cc010000d4010000ea010000f6"
        "01000004020000080200005a0300006e03000084030000d6030000a8050000b8050000c0050000c6050000d6050000fa0500002e060000"
        "6a0600008e0600009e060000e40600003407000074070000657e7b7e817e897e937ea87ead7eb87ebd7ef37efa7e057f19860aaf83b015"
        "cd16cd17cd18cd5e1ca21fbc1f6b6ada80df80e480ea80ef80f480f980ff80018106810f8114811f812181298133814181478152815781"
        "608169816e8184818981938196819f81ae81b181b681bd81c381ca81cc81d181d881de81e781eb81f081f5810d821d822e8261826a82ad"
        "828984a287ab87ad87b387b487c587dd87e3870e88fb88be89408b418b488b538b5c8b618b678b6c8b718b778b7c8b818b868b908b9b8b"
        "a18bad8bb28bb88bd18b51d8db16544a8a42424e8c384c40d47cd87c62cb24d0b504bb049c3f45b1e2106e227122732275227722822295"
        "2299229c229e2268379248eb4d5261d7a003c2a972b572539c89f298f29ff2edf2c7af28b0c4059e35cd35f3350536d938db38e4381239"
        "13396f3973397439773990399139d939da39e339e439e539fc39fd39fe39673a683ab43ab93abb3abc3ac03ac23ac43ad73ad93ada3adb"
        "3a4d3b4e3b523b533b543b5f3b603b613bb53bb63bb73bb83bb93beb3bec3bed3bef3bf93bfa3bfb3bfd3bfe3bfb3cfd3c053d083d153d"
        "173d183d373d383d3d3d3f3d533d553d573d593d5b3d883d8b3d8d3df03df43df73df93d383f3b3f3d3f413f443f603f613f653f683f6a"
        "3f8c3f8e3f943f9b3f9d3fa03fa73fa93ff43ff83ffa3ffe3fea4eef4ef64e014fc051c251c851c951cd51e451e651e851ed51ef51ff55"
        "0156035609560c563156365639563b563e569e57a157a357aa57bf63c263c463cb63cd6320673167346736673d673f679e6ca06ca46ca7"
        "6ca96cdd6cdf6ce36ce66ce86cf2d6f4d6f7d6f9d600d70bd70fd712d714d718d71dd72dd72fd735d738d73ad7513256320c64156460e5"
        "63e565e56ce56ee571e5ef0af10a79e894e8beeedcf127f23cf2d5f261f3a6f3e71d271e9c1e0c2e122e172e202e1f7400a851a866a868"
        "a86fa877a87aa87ca87da881a82cadd7cadccadecae7caedcaeeca31cb35cb41cba4cbabcbadcbafcbb5cbb8cbbacbc1cbc8cb11d817e8"
        "30e835e81c08572868286c28742888288a289428a628b028b128b828c028c328c628092925292b294a294c295e2963299129b629ba29df"
        "2be22beb2bf52bfc2b072c152c1e2c202c2e2c6b2c732c782c8d2c912c942c992c9e2ca02ca62ca72ca92cb22ccb2cd12ce42c0c2d212d"
        "302d502d5c2d6c2d802d822d862d932d972da42dae2dc62dde2de12de32dea2df22d145025502c50bf51ea51eb51ec51ed51ee51f051f1"
        "51f251f351f551f651f751f951025203520452055206520752085209520b52ba55be55c155c455d255d755db55e155e655ec55f255f855"
        "f955015602565e565f56605661566e566f56705671567256735674567656775679567b5684568556875689568f56915692569456965697"
        "5698569a569b569c569d569f56ae56af56b056b256b356b556b656b756b856b956ba56bc56bd56be56bf56c156c256c356c456c556c656"
        "cd56ce56d156d356d456d556d656d856d956da56dc56dd565b6676667766786679667a667b6688668a668c668d668e668f66b467ee6807"
        "6909695b719271bf81fa81bca067c968c9a7c9adc9e9c9efc901ca3bca4fca6cca71ca76ca7cca7fca85ca41cb4ecb63cb77cb7dcb8bcb"
        "b0cb45cc47cc4fcc8fcc0cf12af149f1eaf967fba0fbaefbcefbc2fecbfe53096a09720975097b094519a32294733e605d75658b26af49"
        "ac62eec3f55b009506d421ee3417354739fa391ab18004000935090245f845064d11714575e199029a359a5d9a689a769aa19cdb9d709e"
        "0bc61911ba11e6110a120914643aff3b324d8555136cec6ce26dee7bcf7d5e8fd393ec93159475aa06b508b558b568b598c44adaa9da26"
        "18a71ab31a14472c485b4ed94fab59325a4690bd9d879e969e7aa08ea0fca594a677a888a890a89ea8b4a898ac89ade3bf18c0b2c527cf"
        "82e084ec4f208520872053215a219721674118421a42598c5e8c658c688c8afe2bff2eff86ff88ff70286c29512ab234b450c050587433"
        "78d40d090e94411a587d6981a48ea4aaa4ada4b5a4c2a4c4a453a558a56aa56da581a583a58ba593a59fa5a2a5a4a5ada5b0a599a79da7"
        "a2a76ea873a878a87ca88ca892a8cfa8e538ca44bf637c78a678157b5f7e627e76985ba795ad5dc666c670c696c69fc643c766ca10d53c"
        "d544d549d54dd550d555d557d55ad55bd563d567d574d57fd581d58ad592d5a0d5a3d5add531e801e93707650783095918ce19e859855f"
        "146053612c869587b88a739f8ea2beb7fdb71cb800bf37bf45bf6fbf8ae4cfe4d5e48de5a5e5a8e5ace5cce5b5f8a6fa47fb711a8b1a9b"
        "1aa21aad1ae91a792bfe3ea6401f426e427d4288429542b542")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey4{*silkworm::from_hex("259c334871a9d75d3364e17316299e72bd97b04900000000006ddd03")};
    static Bytes kAccountHistoryValue4{*silkworm::from_hex(
        "0100000000000000000000003a300000020000006d000f006f000d00180000003800000021b724b729b72cb735b738b73bb73db740b742"
        "b745b747b74ab74db74fb703ddc585ca85d485d785db85e085e185e285e685ea85ec85ef85f385f785")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey4}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey4, kAccountHistoryValue4};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey5{*silkworm::from_hex("5aa6b79a8ea7c240c8de59a83765ac984912a8f300000000006ddd03")};
    static Bytes kAccountHistoryValue5{*silkworm::from_hex(
        "0100000000000000000000003a300000020000006c0011006d006400180000003c000000dcf276f3c3f320f442f4dcf4eff4f9f423f6ef"
        "f68bf72bf840fbb1fcdbfcf7fd90ffe6ffe4008d01060daf0dff14e417c41cc31d0f21ea224d35f1367b3b2f3e343f4841be41f6427244"
        "a5454448ae48174938497249344ab34b024c0e4c344dd24dfe4d745430556e557755b5554756a256e8570d589058f1588559e659ec59f5"
        "597f5a895a095b0c5b3f5b805bd75be75e2e5f605f246153618e611a631d66a866b2665267e469b46cce6ccf6cd46ea26fd77109730b73"
        "6e74cc77d077c178687ef88d709cedab42d14ad158d160d166d16cd172d177d17cd183d1c5d931e8fee8c8facafacffae0fae6fa19f"
        "b")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey5}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey5, kAccountHistoryValue5};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey6{*silkworm::from_hex("1e8ab45d1519aa26cee0c24476689e215db7955b00000000006ddd03")};
    static Bytes kAccountHistoryValue6{*silkworm::from_hex(
        "0100000000000000000000003a300000050000006d009c026e002a00700001007100020072000100300000006a050000c0050000c40500"
        "00ca05000016891b89258937893c893f8942894589468948894e896989708980898189828987898989a289ae89b089bd89cd89d189eb89"
        "fa890b8a0c8a188a348a3d8a4d8a598a5b8a608a778aa48aa68aae8ab08ab28acb8acd8ad08ad28adb8a028b048b608b618b768b9e8baa"
        "8bb98b298c4c8c848c958c9b8caa8cad8cbb8cc78cd98cde8cf28c048d278d288d388d398d3c8d4a8d4b8d598d6d8d728d768d788d8f8d"
        "b08dc18dcd8dd68ddf8dfe8d178e198e228e418e428e488e668e868e878e998e9b8eab8ed48ee68efa8e048f358f3c8fcf8fe98f1d901e"
        "901f9052900e91469152917391749182918791a091ab91ac9112922892459247951396319663986d989998ab98ae98be98bf98c098c198"
        "c2982a99499956995999c599d599d999db99dc99dd99e499e799e899ef991c9a2b9a3c9a689a769a779a899a919a969ad19ad79ad99ada"
        "9a6f9ba39bcc9bcd9b149c249c639cf19c139d1a9d1b9d609d879d8f9da99dab9dd19de39d209e3c9e599e759e7d9ea89e549f669f6a9f"
        "6b9f989fbb9fe39fe69fe99f04a027a028a02aa035a045a051a05fa064a067a073a07ca0a0a0b5a017a13da17fa18aa190a19ba10ea28e"
        "a2f3a2f6a2f8a2ffa20aa336a338a351a35da374a3aba3b9a3caa3cba3cda3d2a3d4a3d6a3dba3dca3f0a3f4a30ba438a44da45ba45ca4"
        "68a47ea487a48aa48ea48fa490a492a49aa49ba49ca49da4a6a4b9a4dca421a55ea563a564a565a566a568a56aa56ca572a592a5c2a501"
        "a603a604a60ba60ca628a636a6b1a6c5a6dea6eca6f4a624a72ba7a8a7cfa742a8b7a8eea8e5ab41ae8fafa9afffaf01b05ab0d6b094b1"
        "cfb1deb13db288b290b2beb2c0b2c3b2c7b2cab2e8b2eab20cb346b372b385b387b398b3b3b3d8b3d9b306b413b41eb436b455b481b49e"
        "b4b2b403b532b561b572b5b1b5b6b5efb561b682b689b68bb6c0b6ceb60db711b719b71cb767b770b790b798b7a7b7abb7c0b7c1b7d9b7"
        "e7b7edb7f5b722b831b8b4b8b9b8d6b8d7b8dbb8ddb8f5b819b91eb931b969b97db987b993b9d4b9e3b9e4b9e5b9ecb9efb9f0b915ba1f"
        "ba21ba74bafaba3dbb9dbbbebbdabb05bc1fbc37bc57bc5abc7cbc8cbca0bcb6bce4bceebc7fbde8bdeabd6dbe6ebee5be7fc18cc617c7"
        "19c71ac755c7abc71cc81dc820c828c866c86ac87bc8c2c8d2c871c972c977c979c9cdc9e3c930ca67ca68ca86cad1cad2cae4cae8cafd"
        "ca00cb05cb0acb20cb23cb2dcb35cb3bcb72cb96cba0cba6cbb7cbc9cbcfcbe0cbf0cb10cc17cc37cc47cc5ccc5fcc6ccc6dccc9ccf7cc"
        "fbcc09cd51cd5fcda9cddecd86ceedcef2ce0ccf24cf41cf4ecf6fcf9acfa3cfb3cfd9cfdecfeacf09d03dd046d070d095d0b1d0c4d0cd"
        "d0e6d002d105d11fd15ad16cd19dd1d2d13fd240d24ed25cd279d285d28ed21ad320d302d427d421d529d864d8c9d874d90fda80db97db"
        "a5dbf7dbf8db48dc4adc87dcc0dcd9dcf6dc03dd05dd11dd1cdd1ddd1fdd39dd5bdd75dd76dd7edda0dddbddf4ddfddd00de04de18de1e"
        "de40dea8dea9deaede80df88dfbfdf77e04de190e191e199e143e248e267e2e4e2f3e203e307e32ee349e34de35fe37be382e387e395e3"
        "9fe3b0e3b8e3cfe3d4e382e49de4d8e406e679e6b3e6e0e602e729e72ae735e73de74ce7c3e7cbe7e9e7f9e700e81ae81de81fe821e882"
        "e886e888e817e982e900ea3beaedea97ed1aee35ef36ef38ef1af19bf29cf29df29ef26bf36ff3cff3d9f36df493f4b7f4def4dff4e0f4"
        "2af52ef530f53cf591f595f59ef5d1f5f8f575f681f6b2f6bff6eaf6f7f60af725f728f748f7a3f7aef7bff7e3f701f862f876f88ff8c7"
        "f82af937f947fa7cfa03fb2ffbd5fc53fd61fde7fe9cff05000f00af0090016e031704550478057b058a053907c508f908420a940a740b"
        "cc0b050ded0d190e5d0e780eaa0e160f470ffe0f071020102e10381008112b127713cc132614271434145e14fc152016cd186a1a101b0a"
        "153015950e95bd97bdc35e85fc")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey6}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey6, kAccountHistoryValue6};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey7{*silkworm::from_hex("6871c5aaa4e06861c86978cacf992471355b733000000000006ddd03")};
    static Bytes kAccountHistoryValue7{*silkworm::from_hex("0100000000000000000000003a300000010000006c00000010000000cbf2")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey7}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey7, kAccountHistoryValue7};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey8{*silkworm::from_hex("000000000000000000000000000000000000000000000000006ddd03")};
    static Bytes kAccountHistoryValue8{*silkworm::from_hex(
        "0100000000000000000000003a3000001c00000053001200540054005500010056000100570005005800030059000a005a0005005b0006"
        "005c0001005d00a8005e0009005f000a00600028006100e80062000700630003006400020065000700660011006700190068001d006900"
        "11006a0007006b0022006c0027006d001f006e000e00e80000000e010000b8010000bc010000c0010000cc010000d4010000ea010000f6"
        "01000004020000080200005a0300006e03000084030000d6030000a8050000b8050000c0050000c6050000d6050000fa0500002e060000"
        "6a0600008e0600009e060000e40600003407000074070000657e7b7e817e897e937ea87ead7eb87ebd7ef37efa7e057f19860aaf83b015"
        "cd16cd17cd18cd5e1ca21fbc1f6b6ada80df80e480ea80ef80f480f980ff80018106810f8114811f812181298133814181478152815781"
        "608169816e8184818981938196819f81ae81b181b681bd81c381ca81cc81d181d881de81e781eb81f081f5810d821d822e8261826a82ad"
        "828984a287ab87ad87b387b487c587dd87e3870e88fb88be89408b418b488b538b5c8b618b678b6c8b718b778b7c8b818b868b908b9b8b"
        "a18bad8bb28bb88bd18b51d8db16544a8a42424e8c384c40d47cd87c62cb24d0b504bb049c3f45b1e2106e227122732275227722822295"
        "2299229c229e2268379248eb4d5261d7a003c2a972b572539c89f298f29ff2edf2c7af28b0c4059e35cd35f3350536d938db38e4381239"
        "13396f3973397439773990399139d939da39e339e439e539fc39fd39fe39673a683ab43ab93abb3abc3ac03ac23ac43ad73ad93ada3adb"
        "3a4d3b4e3b523b533b543b5f3b603b613bb53bb63bb73bb83bb93beb3bec3bed3bef3bf93bfa3bfb3bfd3bfe3bfb3cfd3c053d083d153d"
        "173d183d373d383d3d3d3f3d533d553d573d593d5b3d883d8b3d8d3df03df43df73df93d383f3b3f3d3f413f443f603f613f653f683f6a"
        "3f8c3f8e3f943f9b3f9d3fa03fa73fa93ff43ff83ffa3ffe3fea4eef4ef64e014fc051c251c851c951cd51e451e651e851ed51ef51ff55"
        "0156035609560c563156365639563b563e569e57a157a357aa57bf63c263c463cb63cd6320673167346736673d673f679e6ca06ca46ca7"
        "6ca96cdd6cdf6ce36ce66ce86cf2d6f4d6f7d6f9d600d70bd70fd712d714d718d71dd72dd72fd735d738d73ad7513256320c64156460e5"
        "63e565e56ce56ee571e5ef0af10a79e894e8beeedcf127f23cf2d5f261f3a6f3e71d271e9c1e0c2e122e172e202e1f7400a851a866a868"
        "a86fa877a87aa87ca87da881a82cadd7cadccadecae7caedcaeeca31cb35cb41cba4cbabcbadcbafcbb5cbb8cbbacbc1cbc8cb11d817e8"
        "30e835e81c08572868286c28742888288a289428a628b028b128b828c028c328c628092925292b294a294c295e2963299129b629ba29df"
        "2be22beb2bf52bfc2b072c152c1e2c202c2e2c6b2c732c782c8d2c912c942c992c9e2ca02ca62ca72ca92cb22ccb2cd12ce42c0c2d212d"
        "302d502d5c2d6c2d802d822d862d932d972da42dae2dc62dde2de12de32dea2df22d145025502c50bf51ea51eb51ec51ed51ee51f051f1"
        "51f251f351f551f651f751f951025203520452055206520752085209520b52ba55be55c155c455d255d755db55e155e655ec55f255f855"
        "f955015602565e565f56605661566e566f56705671567256735674567656775679567b5684568556875689568f56915692569456965697"
        "5698569a569b569c569d569f56ae56af56b056b256b356b556b656b756b856b956ba56bc56bd56be56bf56c156c256c356c456c556c656"
        "cd56ce56d156d356d456d556d656d856d956da56dc56dd565b6676667766786679667a667b6688668a668c668d668e668f66b467ee6807"
        "6909695b719271bf81fa81bca067c968c9a7c9adc9e9c9efc901ca3bca4fca6cca71ca76ca7cca7fca85ca41cb4ecb63cb77cb7dcb8bcb"
        "b0cb45cc47cc4fcc8fcc0cf12af149f1eaf967fba0fbaefbcefbc2fecbfe53096a09720975097b094519a32294733e605d75658b26af49"
        "ac62eec3f55b009506d421ee3417354739fa391ab18004000935090245f845064d11714575e199029a359a5d9a689a769aa19cdb9d709e"
        "0bc61911ba11e6110a120914643aff3b324d8555136cec6ce26dee7bcf7d5e8fd393ec93159475aa06b508b558b568b598c44adaa9da26"
        "18a71ab31a14472c485b4ed94fab59325a4690bd9d879e969e7aa08ea0fca594a677a888a890a89ea8b4a898ac89ade3bf18c0b2c527cf"
        "82e084ec4f208520872053215a219721674118421a42598c5e8c658c688c8afe2bff2eff86ff88ff70286c29512ab234b450c050587433"
        "78d40d090e94411a587d6981a48ea4aaa4ada4b5a4c2a4c4a453a558a56aa56da581a583a58ba593a59fa5a2a5a4a5ada5b0a599a79da7"
        "a2a76ea873a878a87ca88ca892a8cfa8e538ca44bf637c78a678157b5f7e627e76985ba795ad5dc666c670c696c69fc643c766ca10d53c"
        "d544d549d54dd550d555d557d55ad55bd563d567d574d57fd581d58ad592d5a0d5a3d5add531e801e93707650783095918ce19e859855f"
        "146053612c869587b88a739f8ea2beb7fdb71cb800bf37bf45bf6fbf8ae4cfe4d5e48de5a5e5a8e5ace5cce5b5f8a6fa47fb711a8b1a9b"
        "1aa21aad1ae91a792bfe3ea6401f426e427d4288429542b542")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey8}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey8, kAccountHistoryValue8};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey9{*silkworm::from_hex("000000000000000000000000000000000000000600000000006ddd03")};
    static Bytes kAccountHistoryValue9{*silkworm::from_hex("0100000000000000000000003a3000000100000000000000100000000000")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey9}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey9, kAccountHistoryValue9};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey10{*silkworm::from_hex("000000000000000000000000000000000000000700000000006ddd03")};
    static Bytes kAccountHistoryValue10{*silkworm::from_hex("0100000000000000000000003a300000020000000000000076000000180000001a0000000000f003")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey10}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey10, kAccountHistoryValue10};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey11{*silkworm::from_hex("000000000000000000000000000000000000000800000000006ddd03")};
    static Bytes kAccountHistoryValue11{*silkworm::from_hex("0100000000000000000000003a3000000100000000000000100000000000")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey11}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey11, kAccountHistoryValue11};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey12{*silkworm::from_hex("8aa50579a254382ddbca33b0729f84090d9dcb7400000000006ddd03")};
    static Bytes kAccountHistoryValue12{*silkworm::from_hex(
        "0100000000000000000000003a3000000b0000006b000e006c000e006d0003006e000200700000007100000072001d0073007000740037"
        "007500360076001600600000007e0000009c000000a4000000aa000000ac000000ae000000ea000000cc0100003c020000aa0200001d31"
        "a0316135623542544d54545453757475a880ac802188ad88d1e3dfe36f3451395639e5398d509c509e50a550a7643cbc47bcfaf40df50f"
        "f511f55222fcdc03dd46dd0823524ff1bd6f4ef0f056745e7463749974a474a874b974bc7470a528a60ea712a715a723a725a72fa733a7"
        "6ba78ba79ea71dc428c42bc433c437c43ac43fc4a8d839f204fcbe09df09e409ee09fe0a010b190b290b360b790ba20fe00fe10fe80ff3"
        "0f331f931fef27f42702288a369e36a036b036b336ba36c536d43645394839e839e83def3df83d023e0a3e103e283e483e623e6a3e713e"
        "7e3e873e9b3ea03eac3eb23eb93ebb3ec03ec33ec83ecc3ecf3ed33edb3ee63ee73ef13ef83efb3ed342dc422a4338433a433c435443ab"
        "43ae43b043b343b943bc43f143f4431e442944994f755d7c5d266630663666d367c169c46996819981a181a581a881b081be81ce81e383"
        "ea83629d669d689d9a9d9d9df1b202b303b305b306b307b30bb3c3cec7cea2e10314ed2cee2cf02cf22cf52cf72cf92c012d042d202d28"
        "2d2d2d302d372d382d3e2d422d492dff2d622e8336ea43dc594d8951897e8d858d9293949397939c93a093a393ae93ba93c793ca93cb93"
        "d093d493d793da93dc93de93e593e893ec93f093f393f693bdb6c0b6cfb631d735d7320747095b09883589358a358b358e3590359335a5"
        "35b035aa57b257b557b857ba57bc57ea570a6211626a7182718a7190719c71a671b571bb71cf91d29137a948a954a97db87fb881b884b8"
        "87b88eb897b8a1b8a5b8adb8b1b8b4b8b6b8b9b8bcb8c0b8a3d0bad0c0d051ec6cecf22df52dd7308c453556845c885c895c14731673b0"
        "80b596b79629972b973a9758976097629738a1bab8c3b8c6b8")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey12}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey12, kAccountHistoryValue12};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey13{*silkworm::from_hex("cbebcd41ceabbc85da9bb67527f58d69ad4dfff500000000006ddd03")};
    static Bytes kAccountHistoryValue13{*silkworm::from_hex(
        "0100000000000000000000003a300000010000006d00c003100000008bd08dd08fd092d095d09dd09fd0a0d0a4d0a6d0a7d0a8d0acd0b1"
        "d0b2d0b3d0b4d0c0d0c1d0c8d0cdd0ced0d0d0d2d0d3d0d4d0d5d0d7d0d9d0dad0ded0e1d0e4d0e6d0e7d0e8d0e9d0ebd0eed0f6d0f8d0"
        "f9d0fbd0fdd000d103d105d106d107d108d10cd10dd10ed111d114d116d117d11bd11cd121d122d124d129d12ad12bd12ed130d135d137"
        "d13cd13dd13fd140d141d145d146d14ad14ed14fd150d153d155d15ad15bd15cd15dd15fd161d162d163d166d167d168d169d16cd16dd1"
        "6ed16fd172d173d174d177d179d17cd17ed17fd183d185d187d189d18ed18fd190d192d193d195d198d19ad19cd19dd19fd1a1d1a2d1a6"
        "d1a7d1a9d1abd1add1aed1b1d1b2d1bdd1bed1bfd1c0d1c2d1c5d1c8d1cdd1cfd1d0d1d2d1d9d1e1d1e9d1ead1ebd1f3d1f4d1f5d1f6d1"
        "f7d1f8d1f9d1fad1fbd1fcd1fed1ffd100d202d204d206d208d20bd211d212d213d215d218d21cd21dd21fd220d221d226d22bd22cd22f"
        "d231d232d233d234d235d239d23fd240d241d243d246d249d24ad24bd251d252d253d25cd25dd261d263d264d265d266d269d26cd272d2"
        "74d275d27ed28ad28cd2abd2b0d2c4d2c6d2c8d2ebd2fcd20dd310d313d315d31bd31fd320d321d322d329d32bd32fd330d331d336d337"
        "d339d33bd33fd346d34ed352d353d356d35ad35dd35fd366d36ad36dd371d373d375d377d37ad37cd37ed380d381d38ad38bd38dd38fd3"
        "93d397d398d39ad39cd39dd39ed39fd3a4d3a8d3aad3acd3add3b1d3b2d3b3d3bdd3bed3c2d3c3d3d1d3d2d3d4d3d5d3ddd3e2d3ebd3ed"
        "d3f1d3f6d30ad40dd418d41bd41cd41ed41fd420d421d423d425d427d428d42fd430d432d438d441d442d446d447d44ad44ed450d453d4"
        "5ed45fd460d461d462d467d468d46ad470d473d476d478d47ad47cd483d485d486d489d48bd48cd48dd48ed490d491d493d495d497d49a"
        "d49bd49fd4a2d4a3d4a4d4a8d4a9d4aad4abd4acd4add4aed4afd4b1d4b3d4b5d4b7d4b9d4bbd4bcd4bed4c0d4c1d4c3d4c5d4c7d4c8d4"
        "cad4cbd4ced4cfd4d0d4d2d4d3d4d5d4d7d4d8d4d9d4dad4dcd4ded4e0d4e1d4e4d4e5d4e7d4e8d4ead4edd4eed4efd4f2d4f3d4f4d4f6"
        "d4f7d4f9d4fcd4fed4ffd400d501d504d506d509d50bd50cd50ed511d512d514d516d518d51bd51cd523d526d529d52ad52fd531d535d5"
        "38d53ad53cd540d541d542d546d548d54ad54cd54ed550d553d557d559d55ad55cd55dd55fd560d562d566d567d56cd570d57bd57dd584"
        "d598d59dd59ed5acd5b0d5b4d5b5d5b9d5c0d5c3d5cad5cfd5d5d5dcd5dfd5e0d5e1d5e4d5e7d5e8d5ead5ebd5f2d5f7d507d609d60ed6"
        "14d616d621d623d625d628d62dd62fd638d63ad640d644d646d64cd65ad65ed671d673d675d679d67ad67bd687d688d68bd694d69ad6a2"
        "d6afd6b2d6b9d6c0d6c6d6c7d6cad6ced6cfd6d1d6d3d6d8d6d9d6e0d6ead6eed6f1d6fcd603d70ad70dd710d716d71ad71cd71dd71fd7"
        "23d727d728d72bd72dd72ed72fd730d734d735d73dd73fd74fd750d759d75ad75fd765d76ad774d776d799d79fd7a3d7abd7acd7b0d7b2"
        "d7b8d7bfd7c0d7cad7cfd7e1d7e9d7f6d7fbd7fed71fd822d835d844d84bd84ed855d87ed87fd888d893d896d8a6d8b1d8bad8c3d8d5d8"
        "d8d8e7d8f6d839d94bd966d971d987d98ed99ed9d0d9e5d9ebd9f3d900da0eda10da26da2bda38da3fda49da4cda5dda67da82da8ada8b"
        "da91da9bdaa3daa6dac3dac7dad1dad6dadcdadfdae2dae7daeedaf8dafbda03db24db38db45db51db54db57db58db59db62db72db89db"
        "8edb90db92db93db97db9bdb9fdbaddbaedbbcdbbfdbc1dbc2dbd5dbd8dbdfdbe7dbe9dbeadbf0dbf2dbf4dbf5dbfcdb04dc05dc0fdc13"
        "dc14dc1adc1cdc20dc28dc29dc34dc47dc49dc51dc52dc55dc56dc59dc5cdc61dc65dc68dc6fdc71dc76dc7adc7cdc7fdc83dc8cdc93dc"
        "95dc9cdca6dca9dcafdcb4dcbbdcbcdcc2dcc4dcc5dcd1dcd2dcd3dcd8dcdbdcdddcdedce3dce4dceedcefdcf6dcfcdc03dd05dd0add0c"
        "dd0ddd0edd11dd18dd19dd1edd24dd25dd2add2cdd2ddd2edd35dd39dd3add40dd42dd44dd46dd4ddd55dd56dd57dd58dd5cdd60dd64dd"
        "66dd6cdd6edd6fdd73dd74dd78dd80dd81dd82dd83dd85dd8add8ddd93dd95dd98dd99dd9bdda6dda7ddaaddadddafddb2ddb3ddb4ddbe"
        "ddc7ddcdddd3ddd7ddd8dddadddbdde7ddecddf4ddfddd04de0dde0fde13de16de18de1dde1ede20de21de23de27de2ade2cde2dde2fde"
        "36de39de41de44de47de48de4ade4bde5fde68de69de6cde6ede81de87de88de8ade8ede8fde91de96de9bde9edea1dea4dea7dea8deab"
        "deb3deb4deb9debcdec0dec6decddecfded3ded4dedcdedfdee5deeadeebdeeddeefdef6def7defbde04df05df07df0ddf0fdf10df16df"
        "17df18df1adf1cdf23df25df2bdf30df34df35df36df39df3cdf3fdf46df51df52df57df58df5adf5cdf65df6cdf72df73df77df79df7b"
        "df7edf80df82df85df87df8cdf8fdf90df92df94df95df99df9cdfa0dfa2dfa6dfa9dfabdfb2dfb6dfb8dfbcdfbfdfc3dfc4dfc5dfcadf"
        "d2dfd8dfd9dfdcdfdddfe5dfe9dfebdfeddfefdff2dff3dff7df00e004e005e006e007e008e009e00ae00be00de019e01be01de024e025"
        "e026e028e02be02ee032e03ae03ce047e048e04ae057e058e0")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey13}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey13, kAccountHistoryValue13};
        }));

    // TransactionDatabase::get: TABLE AccountHistory> 1
    static Bytes kAccountHistoryKey14{*silkworm::from_hex("a0f968eba6bbd08f28dc061c7856c1572598339500000000006ddd03")};
    static Bytes kAccountHistoryValue14{*silkworm::from_hex(
        "0100000000000000000000003a300000010000006d00c0031000000046d849d84bd84ed852d853d855d856d85ad85fd863d866d86bd86f"
        "d870d874d877d87bd87ed87fd883d886d888d88bd88fd893d896d898d89cd8a0d8a4d8a6d8a8d8add8b1d8b2d8b5d8b8d8bad8bdd8bed8"
        "c2d8c3d8c6d8cad8cfd8d3d8d4d8d5d8d7d8d8d8dbd8e0d8e4d8e7d8e8d8e9d8edd8f1d8f5d8f6d8f9d8fdd803d907d90bd90fd913d917"
        "d91cd91fd925d92ad92dd931d935d939d93dd941d946d94ad94bd94ed952d957d95ad95ed962d966d96bd96ed971d972d973d977d97bd9"
        "7fd983d987d98bd98ed98fd994d999d99bd99dd99ed9a3d9a6d9abd9afd9b3d9b8d9bbd9bfd9c4d9c9d9cdd9ced9d0d9d1d9d7d9dad9df"
        "d9e3d9e5d9e7d9ebd9efd9f3d9f4d9f9d9fdd900da01da02da06da07da09da0eda10da11da15da16da1bda1fda20da24da26da28da2bda"
        "2fda33da38da3cda3fda40da44da48da49da4cda51da54da5ada5dda5fda62da64da67da6cda6dda71da72da75da79da7dda82da85da8a"
        "da8bda8fda91da93da94da96da97da9bda9edaa0daa3daa4daa6daa8daaddab0dab5dab6dab8dabcdac1dac3dac6dac7dac9dacddad1da"
        "d5dad6dadbdadcdadddadfdae2dae6dae7daeadaeedaf3daf6daf7daf8dafadafbdaffda02db03db07db0bdb0fdb14db17db18db1ddb1e"
        "db22db24db26db2adb2fdb32db36db38db3adb3bdb3fdb43db45db47db4bdb4fdb51db53db54db57db58db59db5cdb61db62db65db69db"
        "6adb6ddb6edb72db75db7adb7edb81db86db89db8adb8edb90db92db93db96db97db9adb9bdb9edb9fdba2dba3dba4dba7dbabdbaddbae"
        "dbb2dbb7dbbcdbbfdbc0dbc1dbc2dbc4dbc8dbccdbd0dbd4dbd5dbd8dbdddbdedbdfdbe1dbe5dbe7dbe9dbeadbeddbf0dbf2dbf4dbf5db"
        "f6dbf8dbfadbfcdbfedb02dc04dc05dc07dc0adc0cdc0edc0fdc10dc13dc14dc19dc1adc1cdc20dc26dc28dc29dc2ddc30dc31dc34dc35"
        "dc39dc3ddc41dc46dc47dc49dc4adc4ddc4edc51dc52dc55dc56dc59dc5adc5cdc5edc61dc62dc65dc67dc68dc6adc6fdc71dc73dc76dc"
        "77dc7adc7cdc7fdc83dc87dc8bdc8cdc8fdc93dc95dc96dc97dc9cdc9ddca0dca4dca6dca8dca9dcacdcafdcb0dcb4dcb8dcbbdcbcdcc0"
        "dcc2dcc4dcc5dcc8dccadccedcd1dcd2dcd3dcd6dcd8dcdadcdbdcdddcdedce2dce3dce4dce6dcebdceedcefdcf3dcf6dcf7dcfbdcfcdc"
        "ffdc00dd03dd05dd09dd0add0cdd0ddd0edd11dd15dd18dd19dd1cdd1edd22dd24dd25dd2add2cdd2ddd2edd33dd35dd36dd39dd3add3b"
        "dd3edd40dd42dd43dd44dd46dd47dd4cdd4ddd4fdd50dd53dd55dd56dd57dd58dd5cdd60dd64dd66dd68dd69dd6bdd6cdd6edd6fdd70dd"
        "73dd74dd78dd7cdd7ddd80dd81dd82dd83dd85dd8add8ddd91dd93dd95dd96dd98dd99dd9add9bdd9fdda1dda2dda6dda7ddaaddadddae"
        "ddafddb2ddb3ddb4ddb7ddbbddbdddbeddc0ddc3ddc7ddcbddcdddcfddd0ddd3ddd4ddd7ddd8dddadddbdddcdde0dde4dde7dde8ddecdd"
        "edddf1ddf2ddf4ddf5ddf7ddfaddfdddffdd02de03de04de07de09de0cde0dde0fde13de14de16de17de18de1bde1dde1ede1fde20de21"
        "de23de27de2ade2bde2cde2dde2fde34de36de38de39de3cde41de44de47de48de4ade4bde4dde50de51de57de59de5ede5fde63de65de"
        "67de68de69de6cde6ede72de73de77de7bde80de81de83de87de88de8ade8bde8ede8fde91de93de96de98de9bde9edea0dea1dea3dea4"
        "dea7dea8deabdeacdeb0deb3deb4deb9debcdec0dec1dec6decddecfded1ded3ded4ded5ded9dedcdedededfdee2dee5dee6deeadeebde"
        "eddeeedeefdef2def6def7defbdeffde03df04df05df07df0bdf0ddf0fdf10df13df16df17df18df1adf1cdf1fdf23df25df28df2bdf2c"
        "df30df34df35df36df39df3cdf3edf3fdf41df45df46df49df4edf51df52df55df57df58df59df5adf5cdf5edf61df62df65df66df6cdf"
        "6edf72df73df77df79df7adf7bdf7edf80df82df83df85df86df87df88df8adf8cdf8ddf8fdf90df92df94df95df97df99df9bdf9cdf9f"
        "dfa0dfa2dfa4dfa6dfa7dfa9dfaadfabdfafdfb0dfb2dfb4dfb6dfb8dfbcdfbddfbfdfc0dfc3dfc4dfc5dfc9dfcadfccdfd0dfd2dfd5df"
        "d8dfd9dfdcdfdddfe2dfe5dfe9dfeadfebdfeddfefdff2dff3dff6dff7dffadffbdffedf00e002e004e005e006e007e008e009e00ae00b"
        "e00de00ee012e017e019e01ae01be01de01fe024e025e026e027e028e02be02ee02fe032e033e037e03ae03ce040e045e047e048e04ae0"
        "4ce051e055e057e058e059e05ae05de060e061e062e063e065e066e067e069e06ce06ee06fe073e074e075e076e079e07be07de07ee080"
        "e082e084e085e086e087e088e089e08ae08be08de08ee092e096e097e09be09ce09de09ee0a0e0a3e0a5e0a6e0a8e0abe0ade0aee0afe0"
        "b2e0b3e0b5e0b7e0b8e0b9e0bae0bce0bde0bee0bfe0c0e0c1e0c4e0c8e0cae0cbe0cce0cfe0d0e0d2e0d4e0d9e0dae0dbe0dde0dfe0e1"
        "e0e2e0e3e0e4e0e8e0ebe0ece0f1e0f2e0f4e0f5e0f7e0f9e0fbe0fde0ffe000e103e106e10ce110e111e112e114e115e11be11fe124e1"
        "25e127e129e12ee133e135e139e13ee141e142e147e14be151e156e157e158e15ce161e162e164e16be16ce170e171e175e17ae17be17e"
        "e184e18ae190e194e199e19ce19ee1a4e1a7e1aae1ace1b0e1")};
    EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey14}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey14, kAccountHistoryValue14};
        }));

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey2{*silkworm::from_hex("00000000006ddd02")};
    static Bytes kAccountChangeSetSubkey2{*silkworm::from_hex("560f0b51eca3f4c6e5873de9091c8f4c200e8ac1")};
    static Bytes kAccountChangeSetValue2{*silkworm::from_hex("03010607733498fc7960b0")};
    EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName,
                                            silkworm::ByteView{kAccountChangeSetKey2},
                                            silkworm::ByteView{kAccountChangeSetSubkey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue2;
        }));

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey3{*silkworm::from_hex("00000000006de48a")};
    static Bytes kAccountChangeSetSubkey3{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes kAccountChangeSetValue3{*silkworm::from_hex("020949aaae4f54eea7ac03")};
    EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName,
                                            silkworm::ByteView{kAccountChangeSetKey3},
                                            silkworm::ByteView{kAccountChangeSetSubkey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue3;
        }));

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet
    static Bytes kAccountChangeSetKey4{*silkworm::from_hex("00000000006ddd02")};
    static Bytes kAccountChangeSetSubkey4{*silkworm::from_hex("2031832e54a2200bf678286f560f49a950db2ad5")};
    static Bytes kAccountChangeSetValue4{*silkworm::from_hex("030273620a017d326f5579b49dd278")};
    EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName,
                                            silkworm::ByteView{kAccountChangeSetKey4},
                                            silkworm::ByteView{kAccountChangeSetSubkey4}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue4;
        }));

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey5{*silkworm::from_hex("00000000006ddd03")};
    static Bytes kAccountChangeSetSubkey5{*silkworm::from_hex("259c334871a9d75d3364e17316299e72bd97b049")};
    static Bytes kAccountChangeSetValue5{*silkworm::from_hex("0301100806c817f6b3d517ea")};
    EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName,
                                            silkworm::ByteView{kAccountChangeSetKey5},
                                            silkworm::ByteView{kAccountChangeSetSubkey5}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue5;
        }));

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey6{*silkworm::from_hex("00000000006de831")};
    static Bytes kAccountChangeSetSubkey6{*silkworm::from_hex("5aa6b79a8ea7c240c8de59a83765ac984912a8f3")};
    static Bytes kAccountChangeSetValue6{*silkworm::from_hex("0501720101")};
    EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName,
                                            silkworm::ByteView{kAccountChangeSetKey6},
                                            silkworm::ByteView{kAccountChangeSetSubkey6}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue6;
        }));

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey7{*silkworm::from_hex("00000000006ddd03")};
    static Bytes kAccountChangeSetSubkey7{*silkworm::from_hex("1e8ab45d1519aa26cee0c24476689e215db7955b")};
    static Bytes kAccountChangeSetValue7{*silkworm::from_hex("0501010101")};
    EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName,
                                            silkworm::ByteView{kAccountChangeSetKey7},
                                            silkworm::ByteView{kAccountChangeSetSubkey7}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue7;
        }));

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey8{*silkworm::from_hex("00000000007603f0")};
    static Bytes kAccountChangeSetSubkey8{*silkworm::from_hex("0000000000000000000000000000000000000007")};
    static Bytes kAccountChangeSetValue8{*silkworm::from_hex("020101")};
    EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName,
                                            silkworm::ByteView{kAccountChangeSetKey8},
                                            silkworm::ByteView{kAccountChangeSetSubkey8}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue8;
        }));

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey9{*silkworm::from_hex("00000000006ddd03")};
    static Bytes kAccountChangeSetSubkey9{*silkworm::from_hex("8aa50579a254382ddbca33b0729f84090d9dcb74")};
    static Bytes kAccountChangeSetValue9{*silkworm::from_hex("030119080de7343b9e519164")};
    EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName,
                                            silkworm::ByteView{kAccountChangeSetKey9},
                                            silkworm::ByteView{kAccountChangeSetSubkey9}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue9;
        }));

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey10{*silkworm::from_hex("00000000006ddd03")};
    static Bytes kAccountChangeSetSubkey10{*silkworm::from_hex("cbebcd41ceabbc85da9bb67527f58d69ad4dfff5")};
    static Bytes kAccountChangeSetValue10{*silkworm::from_hex("0701010a01ca5b1969fd8b69924a0101")};
    EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName,
                                            silkworm::ByteView{kAccountChangeSetKey10},
                                            silkworm::ByteView{kAccountChangeSetSubkey10}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue10;
        }));

    // TransactionDatabase::get_both_range: TABLE AccountChangeSet> 1
    static Bytes kAccountChangeSetKey11{*silkworm::from_hex("00000000006ddd03")};
    static Bytes kAccountChangeSetSubkey11{*silkworm::from_hex("a0f968eba6bbd08f28dc061c7856c15725983395")};
    static Bytes kAccountChangeSetValue11{*silkworm::from_hex("0701010301d4c00101")};
    EXPECT_CALL(transaction, get_both_range(db::table::kAccountChangeSetName,
                                            silkworm::ByteView{kAccountChangeSetKey11},
                                            silkworm::ByteView{kAccountChangeSetSubkey11}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue11;
        }));

    // TransactionDatabase::get_one: TABLE PlainCodeHash > 1
    static Bytes kPlainCodeHashKey1{*silkworm::from_hex("5aa6b79a8ea7c240c8de59a83765ac984912a8f30000000000000001")};
    static Bytes kPlainCodeHashValue1{*silkworm::from_hex("8137c1344f45306dfb3f3844b3d223d16a6c53054e7780d848f1ddc2bd8c634c")};
    EXPECT_CALL(transaction, get_one(db::table::kPlainCodeHashName, silkworm::ByteView{kPlainCodeHashKey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kPlainCodeHashValue1;
        }));

    // TransactionDatabase::get_one: TABLE PlainCodeHash > 1
    static Bytes kPlainCodeHashKey2{*silkworm::from_hex("1e8ab45d1519aa26cee0c24476689e215db7955b0000000000000001")};
    static Bytes kPlainCodeHashValue2{*silkworm::from_hex("4ffc625d813f3dbb425184ff2249bb4609c011928d16bd33876ea2ea7dc52779")};
    EXPECT_CALL(transaction, get_one(db::table::kPlainCodeHashName, silkworm::ByteView{kPlainCodeHashKey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kPlainCodeHashValue2;
        }));

    // TransactionDatabase::get_one: TABLE PlainCodeHash > 1
    static Bytes kPlainCodeHashKey3{*silkworm::from_hex("cbebcd41ceabbc85da9bb67527f58d69ad4dfff50000000000000001")};
    static Bytes kPlainCodeHashValue3{*silkworm::from_hex("9508ecbc07caa265610cf91425373bd99e31076c88d2b8957e07c64d147645c6")};
    EXPECT_CALL(transaction, get_one(db::table::kPlainCodeHashName, silkworm::ByteView{kPlainCodeHashKey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kPlainCodeHashValue3;
        }));

    // TransactionDatabase::get_one: TABLE PlainCodeHash > 1
    static Bytes kPlainCodeHashKey4{*silkworm::from_hex("a0f968eba6bbd08f28dc061c7856c157259833950000000000000001")};
    static Bytes kPlainCodeHashValue4{*silkworm::from_hex("dcbf995c74c9488cf9772791f62699edd0d26d2a2d90e33920e8b604b44a34f0")};
    EXPECT_CALL(transaction, get_one(db::table::kPlainCodeHashName, silkworm::ByteView{kPlainCodeHashKey4}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kPlainCodeHashValue4;
        }));

    // TransactionDatabase::get_one: TABLE Code > 1
    static Bytes kCodeKey1{*silkworm::from_hex("8137c1344f45306dfb3f3844b3d223d16a6c53054e7780d848f1ddc2bd8c634c")};
    static Bytes kCodeValue1{*silkworm::from_hex(
        "60806040523480156200001157600080fd5b5060043610620000ab5760003560e01c8063a25da83c116200006e578063a25da83c146200"
        "0170578063c5f580921462000187578063cf695688146200019e578063ec7debb014620001b2578063f2fde38b14620001c957600080fd"
        "5b8063262f7e5514620000b05780632a26f23714620000e4578063715018a6146200011b5780638da5cb5b14620001275780639d6f0357"
        "1462000139575b600080fd5b620000c7620000c1366004620007a5565b620001e0565b6040516001600160a01b0390911681526020015b"
        "60405180910390f35b6200010c7f06aeb97f04c9a4f2755b9b616c1f3f68b1fa218a91b7499fb6b91d8d6c6a94cb81565b604051908152"
        "602001620000db565b6200012562000213565b005b6000546001600160a01b0316620000c7565b620000c76200014a366004620007a556"
        "5b80516020818301810180516001825292820191909301209152546001600160a01b031681565b6200012562000181366004620007e656"
        "5b6200022b565b6200012562000198366004620008e3565b62000257565b600254620000c7906001600160a01b031681565b6200012562"
        "0001c3366004620007a5565b6200051e565b62000125620001da366004620007e6565b62000591565b6000600182604051620001f49190"
        "620009f3565b908152604051908190036020019020546001600160a01b031692915050565b6200021d62000614565b6200022960006200"
        "0670565b565b6200023562000614565b600280546001600160a01b0319166001600160a01b0392909216919091179055565b6000600160"
        "0160a01b0316600186604051620002749190620009f3565b908152604051908190036020019020546001600160a01b0316146200032157"
        "600185604051620002a59190620009f3565b90815260405190819003602001812054630be0f90d60e01b82526001600160a01b03169063"
        "0be0f90d90620002e7903390889088908890889060040162000a36565b600060405180830381600087803b1580156200030257600080fd"
        "5b505af115801562000317573d6000803e3d6000fd5b5050505062000517565b60003086600260009054906101000a90046001600160a0"
        "1b03167f06aeb97f04c9a4f2755b9b616c1f3f68b1fa218a91b7499fb6b91d8d6c6a94cb60405180604001604052806001815260200160"
        "0160fe1b8152508a6040518060400160405280600681526020016508195b585a5b60d21b815250604051602001620003aa939291906200"
        "0ad2565b60408051601f19818403018152828201825260028352610b5960f21b60208481019190915291519092620003e1928e92016200"
        "0b1b565b604051602081830303815290604052604051620003fe90620006c0565b6200040f9695949392919062000b7c565b6040518091"
        "03906000f0801580156200042c573d6000803e3d6000fd5b50905080600187604051620004429190620009f3565b908152604051908190"
        "03602001812080546001600160a01b03939093166001600160a01b0319909316929092179091557f1e1aa30b3246a75186f962ee22084a"
        "8d29e928afe979ecfe8e5669c60d6d5b2c90620004a3908890849062000be6565b60405180910390a1604051630be0f90d60e01b815260"
        "01600160a01b03821690630be0f90d90620004e1903390899089908990899060040162000a36565b600060405180830381600087803b15"
        "8015620004fc57600080fd5b505af115801562000511573d6000803e3d6000fd5b50505050505b5050505050565b620005286200061456"
        "5b6001816040516200053a9190620009f3565b90815260405190819003602001812080546001600160a01b03191690557f58eb120baca2"
        "f2064e7c794ae658a2a8a79d37cbaefdf891fb536c424b2b9bff906200058690839062000c12565b60405180910390a150565b6200059b"
        "62000614565b6001600160a01b038116620006065760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c65"
        "3a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b60648201526084015b604051809103"
        "90fd5b620006118162000670565b50565b6000546001600160a01b03163314620002295760405162461bcd60e51b815260206004820181"
        "905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e65726044820152606401620005fd565b60"
        "0080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f2"
        "8419497f9722a3daafe3b4186f6b6457e09190a35050565b6125ab8062000c2883390190565b634e487b7160e01b600052604160045260"
        "246000fd5b6040805190810167ffffffffffffffff811182821017156200070a576200070a620006ce565b60405290565b600082601f83"
        "01126200072257600080fd5b813567ffffffffffffffff80821115620007405762000740620006ce565b604051601f8301601f19908116"
        "603f011681019082821181831017156200076b576200076b620006ce565b816040528381528660208588010111156200078557600080fd"
        "5b836020870160208301376000602085830101528094505050505092915050565b600060208284031215620007b857600080fd5b813567"
        "ffffffffffffffff811115620007d057600080fd5b620007de8482850162000710565b949350505050565b600060208284031215620007"
        "f957600080fd5b81356001600160a01b03811681146200081157600080fd5b9392505050565b600082601f8301126200082a57600080fd"
        "5b62000834620006e4565b8060408401858111156200084757600080fd5b845b8181101562000863578035845260209384019301620008"
        "49565b509095945050505050565b600082601f8301126200088057600080fd5b604051610d2080820182811067ffffffffffffffff8211"
        "1715620008a857620008a8620006ce565b60405283018185821115620008bc57600080fd5b845b82811015620008d85780358252602091"
        "82019101620008be565b509195945050505050565b6000806000806000610e408688031215620008fd57600080fd5b853567ffffffffff"
        "ffffff8111156200091557600080fd5b620009238882890162000710565b9550506020620009368882890162000818565b945087607f88"
        "01126200094857600080fd5b62000952620006e4565b8060e089018a8111156200096557600080fd5b60608a015b818110156200098e57"
        "6200097f8c8262000818565b8452928401926040016200096a565b508196506200099e8b8262000818565b955050505050620009b48761"
        "012088016200086e565b90509295509295909350565b60005b83811015620009dd578181015183820152602001620009c3565b83811115"
        "620009ed576000848401525b50505050565b6000825162000a07818460208701620009c0565b9190910192915050565b8060005b600281"
        "1015620009ed57815184526020938401939091019060010162000a15565b6001600160a01b0386168152610e408101602062000a578184"
        "018862000a11565b606083018660005b600281101562000a8a5762000a7683835162000a11565b60409290920191908301906001016200"
        "0a5f565b50505062000a9c60e084018662000a11565b61012083018460005b606981101562000ac4578151835291830191908301906001"
        "0162000aa5565b505050509695505050505050565b6000845162000ae6818460208901620009c0565b84519083019062000afc81836020"
        "8901620009c0565b845191019062000b11818360208801620009c0565b0195945050505050565b6000835162000b2f8184602088016200"
        "09c0565b83519083019062000b45818360208801620009c0565b01949350505050565b6000815180845262000b68816020860160208601"
        "620009c0565b601f01601f19169290920160200192915050565b600060018060a01b03808916835260c0602084015262000ba060c08401"
        "8962000b4e565b8188166040850152866060850152838103608085015262000bc2818762000b4e565b91505082810360a084015262000b"
        "d9818562000b4e565b9998505050505050505050565b60408152600062000bfb604083018562000b4e565b905060018060a01b03831660"
        "208301529392505050565b60208152600062000811602083018462000b4e56fe60c06040523480156200001157600080fd5b5060405162"
        "0025ab380380620025ab8339810160408190526200003491620002b8565b8151829082906200004d90600090602085019062000128565b"
        "5080516200006390600190602084019062000128565b505050620000806200007a620000d260201b60201c565b620000d6565b60016001"
        "60a01b0386166080528451620000a290600790602088019062000128565b5050600880546001600160a01b0319166001600160a01b0394"
        "9094169390931790925560a05250620003b4915050565b3390565b600680546001600160a01b038381166001600160a01b031983168117"
        "9093556040519116919082907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a35050565b82"
        "8054620001369062000378565b90600052602060002090601f0160209004810192826200015a5760008555620001a5565b82601f106200"
        "017557805160ff1916838001178555620001a5565b82800160010185558215620001a5579182015b82811115620001a557825182559160"
        "200191906001019062000188565b50620001b3929150620001b7565b5090565b5b80821115620001b35760008155600101620001b8565b"
        "80516001600160a01b0381168114620001e657600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b60008260"
        "1f8301126200021357600080fd5b81516001600160401b0380821115620002305762000230620001eb565b604051601f8301601f199081"
        "16603f011681019082821181831017156200025b576200025b620001eb565b816040528381526020925086838588010111156200027857"
        "600080fd5b600091505b838210156200029c57858201830151818301840152908201906200027d565b83821115620002ae576000838583"
        "0101525b9695505050505050565b60008060008060008060c08789031215620002d257600080fd5b620002dd87620001ce565b60208801"
        "519096506001600160401b0380821115620002fb57600080fd5b620003098a838b0162000201565b96506200031960408a01620001ce56"
        "5b95506060890151945060808901519150808211156200033757600080fd5b620003458a838b0162000201565b935060a0890151915080"
        "8211156200035c57600080fd5b506200036b89828a0162000201565b9150509295509295509295565b600181811c908216806200038d57"
        "607f821691505b602082108103620003ae57634e487b7160e01b600052602260045260246000fd5b50919050565b60805160a0516121ca"
        "620003e16000396000818161025e0152610b2b0152600061022401526121ca6000f3fe608060405234801561001057600080fd5b506004"
        "36106101725760003560e01c8063715018a6116100de578063a25da83c11610097578063cf69568811610071578063cf6956881461035c"
        "578063d5f72ca51461036f578063e985e9c514610382578063f2fde38b146103be57600080fd5b8063a25da83c14610323578063b88d4f"
        "de14610336578063c87b56dd1461034957600080fd5b8063715018a6146102b95780637772a7c1146102c1578063820e93f5146102ef57"
        "80638da5cb5b146102f757806395d89b4114610308578063a22cb4651461031057600080fd5b8063225360191161013057806322536019"
        "1461021f57806323b872dd146102465780632a26f2371461025957806342842e0e146102805780636352211e1461029357806370a08231"
        "146102a657600080fd5b80629a9b7b1461017757806301ffc9a71461019457806306fdde03146101b7578063081812fc146101cc578063"
        "095ea7b3146101f75780630be0f90d1461020c575b600080fd5b600a546101819081565b6040519081526020015b60405180910390f35b"
        "6101a76101a2366004611900565b6103d1565b604051901515815260200161018b565b6101bf6103e2565b60405161018b919061197556"
        "5b6101df6101da366004611988565b610474565b6040516001600160a01b03909116815260200161018b565b61020a6102053660046119"
        "bd565b61049b565b005b61020a61021a366004611b33565b6105b5565b6101df7f00000000000000000000000000000000000000000000"
        "0000000000000000000081565b61020a610254366004611b9e565b6105d1565b6101817f00000000000000000000000000000000000000"
        "0000000000000000000000000081565b61020a61028e366004611b9e565b610602565b6101df6102a1366004611988565b61061d565b61"
        "01816102b4366004611bda565b61067d565b61020a610703565b6101a76102cf366004611c6b565b805160208183018101805160098252"
        "928201919093012091525460ff1681565b6101bf610717565b6006546001600160a01b03166101df565b6101bf6107a5565b61020a6103"
        "1e366004611cc2565b6107b4565b61020a610331366004611bda565b6107c3565b61020a610344366004611cf9565b6107ed565b6101bf"
        "610357366004611988565b610825565b6008546101df906001600160a01b031681565b61020a61037d366004611d75565b610899565b61"
        "01a7610390366004611dcf565b6001600160a01b03918216600090815260056020908152604080832093909416825291909152205460ff"
        "1690565b61020a6103cc366004611bda565b6108a6565b60006103dc8261091f565b92915050565b6060600080546103f190611e02565b"
        "80601f016020809104026020016040519081016040528092919081815260200182805461041d90611e02565b801561046a5780601f1061"
        "043f5761010080835404028352916020019161046a565b820191906000526020600020905b81548152906001019060200180831161044d"
        "57829003601f168201915b5050505050905090565b600061047f8261096f565b506000908152600460205260409020546001600160a01b"
        "031690565b60006104a68261061d565b9050806001600160a01b0316836001600160a01b0316036105185760405162461bcd60e51b8152"
        "60206004820152602160248201527f4552433732313a20617070726f76616c20746f2063757272656e74206f776e656044820152603960"
        "f91b60648201526084015b60405180910390fd5b336001600160a01b038216148061053457506105348133610390565b6105a657604051"
        "62461bcd60e51b815260206004820152603e60248201527f4552433732313a20617070726f76652063616c6c6572206973206e6f742074"
        "6f60448201527f6b656e206f776e6572206e6f7220617070726f76656420666f7220616c6c0000606482015260840161050f565b6105b0"
        "83836109ce565b505050565b6105bd610a3c565b6105ca8585858585610a96565b5050505050565b6105db3382610e22565b6105f75760"
        "405162461bcd60e51b815260040161050f90611e3c565b6105b0838383610ea1565b6105b0838383604051806020016040528060008152"
        "506107ed565b6000818152600260205260408120546001600160a01b0316806103dc5760405162461bcd60e51b81526020600482015260"
        "18602482015277115490cdcc8c4e881a5b9d985b1a59081d1bdad95b88125160421b604482015260640161050f565b60006001600160a0"
        "1b0382166106e75760405162461bcd60e51b815260206004820152602960248201527f4552433732313a2061646472657373207a65726f"
        "206973206e6f7420612076616044820152683634b21037bbb732b960b91b606482015260840161050f565b506001600160a01b03166000"
        "9081526003602052604090205490565b61070b610a3c565b6107156000611048565b565b6007805461072490611e02565b80601f016020"
        "809104026020016040519081016040528092919081815260200182805461075090611e02565b801561079d5780601f1061077257610100"
        "80835404028352916020019161079d565b820191906000526020600020905b81548152906001019060200180831161078057829003601f"
        "168201915b505050505081565b6060600180546103f190611e02565b6107bf33838361109a565b5050565b6107cb610a3c565b60088054"
        "6001600160a01b0319166001600160a01b0392909216919091179055565b6107f73383610e22565b6108135760405162461bcd60e51b81"
        "5260040161050f90611e3c565b61081f84848484611168565b50505050565b60606108308261096f565b60006108476040805160208101"
        "9091526000815290565b905060008151116108675760405180602001604052806000815250610892565b806108718461119b565b604051"
        "602001610882929190611e8a565b6040516020818303038152906040525b9392505050565b61081f3385858585610a96565b6108ae610a"
        "3c565b6001600160a01b0381166109135760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e65"
        "77206f776e657220697320746865207a65726f206160448201526564647265737360d01b606482015260840161050f565b61091c816110"
        "48565b50565b60006001600160e01b031982166380ac58cd60e01b148061095057506001600160e01b03198216635b5e139f60e01b145b"
        "806103dc57506301ffc9a760e01b6001600160e01b03198316146103dc565b6000818152600260205260409020546001600160a01b0316"
        "61091c5760405162461bcd60e51b8152602060048201526018602482015277115490cdcc8c4e881a5b9d985b1a59081d1bdad95b881251"
        "60421b604482015260640161050f565b600081815260046020526040902080546001600160a01b0319166001600160a01b038416908117"
        "9091558190610a038261061d565b6001600160a01b03167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b9"
        "2560405160405180910390a45050565b6006546001600160a01b031633146107155760405162461bcd60e51b8152602060048201819052"
        "60248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604482015260640161050f565b6000610a"
        "a18261129c565b9050600981604051610ab39190611eb9565b9081526040519081900360200190205460ff161515600103610b23576040"
        "5162461bcd60e51b815260206004820152602360248201527f54686973205a4b2070726f6f662068617320616c7265616479206265656e"
        "20756044820152621cd95960ea1b606482015260840161050f565b610d008201517f000000000000000000000000000000000000000000"
        "000000000000000000000014610bae5760405162461bcd60e51b815260206004820152602e60248201527f54686973205a4b2070726f6f"
        "66206973206e6f742066726f6d2074686520636f60448201526d393932b1ba1030ba3a32b9ba37b960911b606482015260840161050f56"
        "5b600060078054610bbd90611e02565b80601f0160208091040260200160405190810160405280929190818152602001828054610be990"
        "611e02565b8015610c365780601f10610c0b57610100808354040283529160200191610c36565b820191906000526020600020905b8154"
        "81529060010190602001808311610c1957829003601f168201915b5050505050905060005b60078054610c4d90611e02565b90508160ff"
        "161015610d1057818160ff1681518110610c6e57610c6e611ed5565b016020015160f81c84610c8283600e611f01565b60ff1660698110"
        "610c9557610c95611ed5565b602002015160ff1614610cfe5760405162461bcd60e51b815260206004820152602b60248201527f546869"
        "73205a4b2070726f6f66206973206e6f742066726f6d2074686520636f60448201526a1c9c9958dd08195b585a5b60aa1b606482015260"
        "840161050f565b80610d0881611f26565b915050610c40565b50600854604051636624120f60e11b81526001600160a01b039091169063"
        "cc48241e90610d47908990899089908990600401611f68565b602060405180830381865afa158015610d64573d6000803e3d6000fd5b50"
        "5050506040513d601f19601f82011682018060405250810190610d889190611fec565b610dc75760405162461bcd60e51b815260206004"
        "820152601060248201526f24b73b30b634b2102d2590383937b7b360811b604482015260640161050f565b610dd987610dd4600a549056"
        "5b611354565b610de7600a80546001019055565b6001600983604051610df99190611eb9565b9081526040519081900360200190208054"
        "91151560ff1990921691909117905550505050505050565b600080610e2e8361061d565b9050806001600160a01b0316846001600160a0"
        "1b03161480610e7557506001600160a01b0380821660009081526005602090815260408083209388168352929052205460ff165b80610e"
        "995750836001600160a01b0316610e8e84610474565b6001600160a01b0316145b949350505050565b826001600160a01b0316610eb482"
        "61061d565b6001600160a01b031614610f185760405162461bcd60e51b815260206004820152602560248201527f4552433732313a2074"
        "72616e736665722066726f6d20696e636f72726563742060448201526437bbb732b960d91b606482015260840161050f565b6001600160"
        "a01b038216610f7a5760405162461bcd60e51b8152602060048201526024808201527f4552433732313a207472616e7366657220746f20"
        "746865207a65726f206164646044820152637265737360e01b606482015260840161050f565b610f8583838361136e565b610f90600082"
        "6109ce565b6001600160a01b0383166000908152600360205260408120805460019290610fb9908490612009565b909155505060016001"
        "60a01b0382166000908152600360205260408120805460019290610fe7908490612020565b909155505060008181526002602052604080"
        "822080546001600160a01b0319166001600160a01b0386811691821790925591518493918716917fddf252ad1be2c89b69c2b068fc378d"
        "aa952ba7f163c4a11628f55a4df523b3ef91a4505050565b600680546001600160a01b038381166001600160a01b031983168117909355"
        "6040519116919082907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a35050565b81600160"
        "0160a01b0316836001600160a01b0316036110fb5760405162461bcd60e51b815260206004820152601960248201527f4552433732313a"
        "20617070726f766520746f2063616c6c657200000000000000604482015260640161050f565b6001600160a01b03838116600081815260"
        "056020908152604080832094871680845294825291829020805460ff191686151590811790915591519182527f17307eab39ab6107e889"
        "9845ad3d59bd9653f200f220920489ca2b5937696c31910160405180910390a3505050565b611173848484610ea1565b61117f84848484"
        "6113c5565b61081f5760405162461bcd60e51b815260040161050f90612038565b6060816000036111c257505060408051808201909152"
        "60018152600360fc1b602082015290565b8160005b81156111ec57806111d68161208a565b91506111e59050600a836120b9565b915061"
        "11c6565b60008167ffffffffffffffff811115611207576112076119e7565b6040519080825280601f01601f1916602001820160405280"
        "15611231576020820181803683370190505b5090505b8415610e9957611246600183612009565b9150611253600a866120cd565b61125e"
        "906030612020565b60f81b81838151811061127357611273611ed5565b60200101906001600160f81b031916908160001a905350611295"
        "600a866120b9565b9450611235565b60608060005b600e81101561134d57806000036112fa57816112d38583606981106112c9576112c9"
        "611ed5565b60200201516114c6565b6040516020016112e4929190611e8a565b604051602081830303815290604052915061133b565b81"
        "6113186113138684606981106112c9576112c9611ed5565b61151d565b604051602001611329929190611e8a565b604051602081830303"
        "81529060405291505b806113458161208a565b9150506112a2565b5092915050565b6107bf828260405180602001604052806000815250"
        "6115cd565b6001600160a01b038316156105b05760405162461bcd60e51b815260206004820152601760248201527f5468697320746f6b"
        "656e20697320736f756c626f756e64000000000000000000604482015260640161050f565b60006001600160a01b0384163b156114bb57"
        "604051630a85bd0160e11b81526001600160a01b0385169063150b7a02906114099033908990889088906004016120e1565b6020604051"
        "808303816000875af1925050508015611444575060408051601f3d908101601f191682019092526114419181019061211e565b60015b61"
        "14a1573d808015611472576040519150601f19603f3d011682016040523d82523d6000602084013e611477565b606091505b5080516000"
        "036114995760405162461bcd60e51b815260040161050f90612038565b805181602001fd5b6001600160e01b031916630a85bd0160e11b"
        "149050610e99565b506001949350505050565b6060816000036114f05750506040805180820190915260048152630307830360e41b6020"
        "82015290565b8160005b811561151357806115048161208a565b915050600882901c91506114f4565b610e998482611600565b60408051"
        "600280825281830190925260609190600490849060009084602082018180368337019050509050835b8360ff168160ff1610156115c357"
        "828160ff168151811061156d5761156d611ed5565b01602001516001600160f81b03191682611587878461213b565b60ff168151811061"
        "159a5761159a611ed5565b60200101906001600160f81b031916908160001a905350806115bb81611f26565b91505061154a565b509594"
        "5050505050565b6115d7838361179c565b6115e460008484846113c5565b6105b05760405162461bcd60e51b815260040161050f906120"
        "38565b6060600061160f83600261215e565b61161a906002612020565b67ffffffffffffffff811115611632576116326119e7565b6040"
        "519080825280601f01601f19166020018201604052801561165c576020820181803683370190505b509050600360fc1b81600081518110"
        "61167757611677611ed5565b60200101906001600160f81b031916908160001a905350600f60fb1b816001815181106116a6576116a661"
        "1ed5565b60200101906001600160f81b031916908160001a90535060006116ca84600261215e565b6116d5906001612020565b90505b60"
        "0181111561174d576f181899199a1a9b1b9c1cb0b131b232b360811b85600f166010811061170957611709611ed5565b1a60f81b828281"
        "51811061171f5761171f611ed5565b60200101906001600160f81b031916908160001a90535060049490941c936117468161217d565b90"
        "506116d8565b5083156108925760405162461bcd60e51b815260206004820181905260248201527f537472696e67733a20686578206c65"
        "6e67746820696e73756666696369656e74604482015260640161050f565b6001600160a01b0382166117f25760405162461bcd60e51b81"
        "5260206004820181905260248201527f4552433732313a206d696e7420746f20746865207a65726f206164647265737360448201526064"
        "0161050f565b6000818152600260205260409020546001600160a01b0316156118575760405162461bcd60e51b81526020600482015260"
        "1c60248201527f4552433732313a20746f6b656e20616c7265616479206d696e74656400000000604482015260640161050f565b611863"
        "6000838361136e565b6001600160a01b038216600090815260036020526040812080546001929061188c908490612020565b9091555050"
        "60008181526002602052604080822080546001600160a01b0319166001600160a01b03861690811790915590518392907fddf252ad1be2"
        "c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef908290a45050565b6001600160e01b03198116811461091c57600080fd"
        "5b60006020828403121561191257600080fd5b8135610892816118ea565b60005b83811015611938578181015183820152602001611920"
        "565b8381111561081f5750506000910152565b6000815180845261196181602086016020860161191d565b601f01601f19169290920160"
        "200192915050565b6020815260006108926020830184611949565b60006020828403121561199a57600080fd5b5035919050565b803560"
        "01600160a01b03811681146119b857600080fd5b919050565b600080604083850312156119d057600080fd5b6119d9836119a1565b9460"
        "20939093013593505050565b634e487b7160e01b600052604160045260246000fd5b6040805190810167ffffffffffffffff8111828210"
        "1715611a2057611a206119e7565b60405290565b600082601f830112611a3757600080fd5b611a3f6119fd565b80604084018581111561"
        "1a5157600080fd5b845b81811015611a6b578035845260209384019301611a53565b509095945050505050565b600082601f830112611a"
        "8757600080fd5b611a8f6119fd565b806080840185811115611aa157600080fd5b845b81811015611a6b57611ab58782611a26565b8452"
        "602090930192604001611aa3565b600082601f830112611ad657600080fd5b604051610d2080820182811067ffffffffffffffff821117"
        "15611afb57611afb6119e7565b60405283018185821115611b0e57600080fd5b845b82811015611b28578035825260209182019101611b"
        "10565b509195945050505050565b6000806000806000610e408688031215611b4c57600080fd5b611b55866119a1565b9450611b648760"
        "208801611a26565b9350611b738760608801611a76565b9250611b828760e08801611a26565b9150611b92876101208801611ac5565b90"
        "509295509295909350565b600080600060608486031215611bb357600080fd5b611bbc846119a1565b9250611bca602085016119a1565b"
        "9150604084013590509250925092565b600060208284031215611bec57600080fd5b610892826119a1565b600067ffffffffffffffff80"
        "841115611c1057611c106119e7565b604051601f8501601f19908116603f01168101908282118183101715611c3857611c386119e7565b"
        "81604052809350858152868686011115611c5157600080fd5b858560208301376000602087830101525050509392505050565b60006020"
        "8284031215611c7d57600080fd5b813567ffffffffffffffff811115611c9457600080fd5b8201601f81018413611ca557600080fd5b61"
        "0e9984823560208401611bf5565b801515811461091c57600080fd5b60008060408385031215611cd557600080fd5b611cde836119a156"
        "5b91506020830135611cee81611cb4565b809150509250929050565b60008060008060808587031215611d0f57600080fd5b611d188561"
        "19a1565b9350611d26602086016119a1565b925060408501359150606085013567ffffffffffffffff811115611d4957600080fd5b8501"
        "601f81018713611d5a57600080fd5b611d6987823560208401611bf5565b91505092959194509250565b600080600080610e2085870312"
        "15611d8c57600080fd5b611d968686611a26565b9350611da58660408701611a76565b9250611db48660c08701611a26565b9150611dc4"
        "866101008701611ac5565b905092959194509250565b60008060408385031215611de257600080fd5b611deb836119a1565b9150611df9"
        "602084016119a1565b90509250929050565b600181811c90821680611e1657607f821691505b602082108103611e3657634e487b7160e0"
        "1b600052602260045260246000fd5b50919050565b6020808252602e908201527f4552433732313a2063616c6c6572206973206e6f7420"
        "746f6b656e206f776e6560408201526d1c881b9bdc88185c1c1c9bdd995960921b606082015260800190565b60008351611e9c81846020"
        "880161191d565b835190830190611eb081836020880161191d565b01949350505050565b60008251611ecb81846020870161191d565b91"
        "90910192915050565b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b600052601160045260246000fd5b6000"
        "60ff821660ff84168060ff03821115611f1e57611f1e611eeb565b019392505050565b600060ff821660ff8103611f3c57611f3c611eeb"
        "565b60010192915050565b8060005b600281101561081f578151845260209384019390910190600101611f49565b610e208101611f7782"
        "87611f45565b60408083018660005b6002811015611fa757611f94838351611f45565b9183019160209190910190600101611f80565b50"
        "505050611fb860c0830185611f45565b61010082018360005b6069811015611fe0578151835260209283019290910190600101611fc156"
        "5b50505095945050505050565b600060208284031215611ffe57600080fd5b815161089281611cb4565b60008282101561201b5761201b"
        "611eeb565b500390565b6000821982111561203357612033611eeb565b500190565b60208082526032908201527f4552433732313a2074"
        "72616e7366657220746f206e6f6e20455243373231526560408201527131b2b4bb32b91034b6b83632b6b2b73a32b960711b6060820152"
        "60800190565b60006001820161209c5761209c611eeb565b5060010190565b634e487b7160e01b600052601260045260246000fd5b6000"
        "826120c8576120c86120a3565b500490565b6000826120dc576120dc6120a3565b500690565b6001600160a01b03858116825284166020"
        "8201526040810183905260806060820181905260009061211490830184611949565b9695505050505050565b6000602082840312156121"
        "3057600080fd5b8151610892816118ea565b600060ff821660ff84168082101561215557612155611eeb565b90039392505050565b6000"
        "81600019048311821515161561217857612178611eeb565b500290565b60008161218c5761218c611eeb565b50600019019056fea26469"
        "70667358221220291bb756f8e522344ab04c3654d52559906dcc8f319583d1b1377a836b30caaa64736f6c634300080e0033a264697066"
        "73582212206d6ee9c1b7e8c5fa246c96922e9d1db63219d0f02b859774e5152cc5d7d6b88e64736f6c634300080e0033")};
    EXPECT_CALL(transaction, get_one(db::table::kCodeName, silkworm::ByteView{kCodeKey1}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kCodeValue1;
        }));

    // TransactionDatabase::get_one: TABLE Code > 1
    static Bytes kCodeKey2{*silkworm::from_hex("4ffc625d813f3dbb425184ff2249bb4609c011928d16bd33876ea2ea7dc52779")};
    static Bytes kCodeValue2{*silkworm::from_hex(
        "608060405234801561001057600080fd5b50600436106101725760003560e01c8063715018a6116100de578063a25da83c116100975780"
        "63cf69568811610071578063cf6956881461035c578063d5f72ca51461036f578063e985e9c514610382578063f2fde38b146103be5760"
        "0080fd5b8063a25da83c14610323578063b88d4fde14610336578063c87b56dd1461034957600080fd5b8063715018a6146102b9578063"
        "7772a7c1146102c1578063820e93f5146102ef5780638da5cb5b146102f757806395d89b4114610308578063a22cb46514610310576000"
        "80fd5b80632253601911610130578063225360191461021f57806323b872dd146102465780632a26f2371461025957806342842e0e1461"
        "02805780636352211e1461029357806370a08231146102a657600080fd5b80629a9b7b1461017757806301ffc9a71461019457806306fd"
        "de03146101b7578063081812fc146101cc578063095ea7b3146101f75780630be0f90d1461020c575b600080fd5b600a54610181908156"
        "5b6040519081526020015b60405180910390f35b6101a76101a2366004611900565b6103d1565b604051901515815260200161018b565b"
        "6101bf6103e2565b60405161018b9190611975565b6101df6101da366004611988565b610474565b6040516001600160a01b0390911681"
        "5260200161018b565b61020a6102053660046119bd565b61049b565b005b61020a61021a366004611b33565b6105b5565b6101df7f0000"
        "000000000000000000005aa6b79a8ea7c240c8de59a83765ac984912a8f381565b61020a610254366004611b9e565b6105d1565b610181"
        "7f06aeb97f04c9a4f2755b9b616c1f3f68b1fa218a91b7499fb6b91d8d6c6a94cb81565b61020a61028e366004611b9e565b610602565b"
        "6101df6102a1366004611988565b61061d565b6101816102b4366004611bda565b61067d565b61020a610703565b6101a76102cf366004"
        "611c6b565b805160208183018101805160098252928201919093012091525460ff1681565b6101bf610717565b6006546001600160a01b"
        "03166101df565b6101bf6107a5565b61020a61031e366004611cc2565b6107b4565b61020a610331366004611bda565b6107c3565b6102"
        "0a610344366004611cf9565b6107ed565b6101bf610357366004611988565b610825565b6008546101df906001600160a01b031681565b"
        "61020a61037d366004611d75565b610899565b6101a7610390366004611dcf565b6001600160a01b039182166000908152600560209081"
        "52604080832093909416825291909152205460ff1690565b61020a6103cc366004611bda565b6108a6565b60006103dc8261091f565b92"
        "915050565b6060600080546103f190611e02565b80601f0160208091040260200160405190810160405280929190818152602001828054"
        "61041d90611e02565b801561046a5780601f1061043f5761010080835404028352916020019161046a565b820191906000526020600020"
        "905b81548152906001019060200180831161044d57829003601f168201915b5050505050905090565b600061047f8261096f565b506000"
        "908152600460205260409020546001600160a01b031690565b60006104a68261061d565b9050806001600160a01b0316836001600160a0"
        "1b0316036105185760405162461bcd60e51b815260206004820152602160248201527f4552433732313a20617070726f76616c20746f20"
        "63757272656e74206f776e656044820152603960f91b60648201526084015b60405180910390fd5b336001600160a01b03821614806105"
        "3457506105348133610390565b6105a65760405162461bcd60e51b815260206004820152603e60248201527f4552433732313a20617070"
        "726f76652063616c6c6572206973206e6f7420746f60448201527f6b656e206f776e6572206e6f7220617070726f76656420666f722061"
        "6c6c0000606482015260840161050f565b6105b083836109ce565b505050565b6105bd610a3c565b6105ca8585858585610a96565b5050"
        "505050565b6105db3382610e22565b6105f75760405162461bcd60e51b815260040161050f90611e3c565b6105b0838383610ea1565b61"
        "05b0838383604051806020016040528060008152506107ed565b6000818152600260205260408120546001600160a01b0316806103dc57"
        "60405162461bcd60e51b8152602060048201526018602482015277115490cdcc8c4e881a5b9d985b1a59081d1bdad95b88125160421b60"
        "4482015260640161050f565b60006001600160a01b0382166106e75760405162461bcd60e51b815260206004820152602960248201527f"
        "4552433732313a2061646472657373207a65726f206973206e6f7420612076616044820152683634b21037bbb732b960b91b6064820152"
        "60840161050f565b506001600160a01b031660009081526003602052604090205490565b61070b610a3c565b6107156000611048565b56"
        "5b6007805461072490611e02565b80601f016020809104026020016040519081016040528092919081815260200182805461075090611e"
        "02565b801561079d5780601f106107725761010080835404028352916020019161079d565b820191906000526020600020905b81548152"
        "906001019060200180831161078057829003601f168201915b505050505081565b6060600180546103f190611e02565b6107bf33838361"
        "109a565b5050565b6107cb610a3c565b600880546001600160a01b0319166001600160a01b0392909216919091179055565b6107f73383"
        "610e22565b6108135760405162461bcd60e51b815260040161050f90611e3c565b61081f84848484611168565b50505050565b60606108"
        "308261096f565b600061084760408051602081019091526000815290565b90506000815111610867576040518060200160405280600081"
        "5250610892565b806108718461119b565b604051602001610882929190611e8a565b6040516020818303038152906040525b9392505050"
        "565b61081f3385858585610a96565b6108ae610a3c565b6001600160a01b0381166109135760405162461bcd60e51b8152602060048201"
        "52602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d0"
        "1b606482015260840161050f565b61091c81611048565b50565b60006001600160e01b031982166380ac58cd60e01b1480610950575060"
        "01600160e01b03198216635b5e139f60e01b145b806103dc57506301ffc9a760e01b6001600160e01b03198316146103dc565b60008181"
        "52600260205260409020546001600160a01b031661091c5760405162461bcd60e51b8152602060048201526018602482015277115490cd"
        "cc8c4e881a5b9d985b1a59081d1bdad95b88125160421b604482015260640161050f565b60008181526004602052604090208054600160"
        "0160a01b0319166001600160a01b0384169081179091558190610a038261061d565b6001600160a01b03167f8c5be1e5ebec7d5bd14f71"
        "427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92560405160405180910390a45050565b6006546001600160a01b031633146107155760"
        "405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f77"
        "6e6572604482015260640161050f565b6000610aa18261129c565b9050600981604051610ab39190611eb9565b90815260405190819003"
        "60200190205460ff161515600103610b235760405162461bcd60e51b815260206004820152602360248201527f54686973205a4b207072"
        "6f6f662068617320616c7265616479206265656e20756044820152621cd95960ea1b606482015260840161050f565b610d008201517f06"
        "aeb97f04c9a4f2755b9b616c1f3f68b1fa218a91b7499fb6b91d8d6c6a94cb14610bae5760405162461bcd60e51b815260206004820152"
        "602e60248201527f54686973205a4b2070726f6f66206973206e6f742066726f6d2074686520636f60448201526d393932b1ba1030ba3a"
        "32b9ba37b960911b606482015260840161050f565b600060078054610bbd90611e02565b80601f01602080910402602001604051908101"
        "60405280929190818152602001828054610be990611e02565b8015610c365780601f10610c0b5761010080835404028352916020019161"
        "0c36565b820191906000526020600020905b815481529060010190602001808311610c1957829003601f168201915b5050505050905060"
        "005b60078054610c4d90611e02565b90508160ff161015610d1057818160ff1681518110610c6e57610c6e611ed5565b016020015160f8"
        "1c84610c8283600e611f01565b60ff1660698110610c9557610c95611ed5565b602002015160ff1614610cfe5760405162461bcd60e51b"
        "815260206004820152602b60248201527f54686973205a4b2070726f6f66206973206e6f742066726f6d2074686520636f60448201526a"
        "1c9c9958dd08195b585a5b60aa1b606482015260840161050f565b80610d0881611f26565b915050610c40565b50600854604051636624"
        "120f60e11b81526001600160a01b039091169063cc48241e90610d47908990899089908990600401611f68565b60206040518083038186"
        "5afa158015610d64573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610d889190611fec565b"
        "610dc75760405162461bcd60e51b815260206004820152601060248201526f24b73b30b634b2102d2590383937b7b360811b6044820152"
        "60640161050f565b610dd987610dd4600a5490565b611354565b610de7600a80546001019055565b6001600983604051610df99190611e"
        "b9565b908152604051908190036020019020805491151560ff1990921691909117905550505050505050565b600080610e2e8361061d56"
        "5b9050806001600160a01b0316846001600160a01b03161480610e7557506001600160a01b038082166000908152600560209081526040"
        "8083209388168352929052205460ff165b80610e995750836001600160a01b0316610e8e84610474565b6001600160a01b0316145b9493"
        "50505050565b826001600160a01b0316610eb48261061d565b6001600160a01b031614610f185760405162461bcd60e51b815260206004"
        "820152602560248201527f4552433732313a207472616e736665722066726f6d20696e636f72726563742060448201526437bbb732b960"
        "d91b606482015260840161050f565b6001600160a01b038216610f7a5760405162461bcd60e51b8152602060048201526024808201527f"
        "4552433732313a207472616e7366657220746f20746865207a65726f206164646044820152637265737360e01b60648201526084016105"
        "0f565b610f8583838361136e565b610f906000826109ce565b6001600160a01b0383166000908152600360205260408120805460019290"
        "610fb9908490612009565b90915550506001600160a01b0382166000908152600360205260408120805460019290610fe7908490612020"
        "565b909155505060008181526002602052604080822080546001600160a01b0319166001600160a01b0386811691821790925591518493"
        "918716917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef91a4505050565b600680546001600160a01b"
        "038381166001600160a01b0319831681179093556040519116919082907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3"
        "b4186f6b6457e090600090a35050565b816001600160a01b0316836001600160a01b0316036110fb5760405162461bcd60e51b81526020"
        "6004820152601960248201527f4552433732313a20617070726f766520746f2063616c6c65720000000000000060448201526064016105"
        "0f565b6001600160a01b03838116600081815260056020908152604080832094871680845294825291829020805460ff19168615159081"
        "1790915591519182527f17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31910160405180910390a3505050"
        "565b611173848484610ea1565b61117f848484846113c5565b61081f5760405162461bcd60e51b815260040161050f90612038565b6060"
        "816000036111c25750506040805180820190915260018152600360fc1b602082015290565b8160005b81156111ec57806111d68161208a"
        "565b91506111e59050600a836120b9565b91506111c6565b60008167ffffffffffffffff811115611207576112076119e7565b60405190"
        "80825280601f01601f191660200182016040528015611231576020820181803683370190505b5090505b8415610e995761124660018361"
        "2009565b9150611253600a866120cd565b61125e906030612020565b60f81b81838151811061127357611273611ed5565b602001019060"
        "01600160f81b031916908160001a905350611295600a866120b9565b9450611235565b60608060005b600e81101561134d578060000361"
        "12fa57816112d38583606981106112c9576112c9611ed5565b60200201516114c6565b6040516020016112e4929190611e8a565b604051"
        "602081830303815290604052915061133b565b816113186113138684606981106112c9576112c9611ed5565b61151d565b604051602001"
        "611329929190611e8a565b60405160208183030381529060405291505b806113458161208a565b9150506112a2565b5092915050565b61"
        "07bf8282604051806020016040528060008152506115cd565b6001600160a01b038316156105b05760405162461bcd60e51b8152602060"
        "04820152601760248201527f5468697320746f6b656e20697320736f756c626f756e64000000000000000000604482015260640161050f"
        "565b60006001600160a01b0384163b156114bb57604051630a85bd0160e11b81526001600160a01b0385169063150b7a02906114099033"
        "908990889088906004016120e1565b6020604051808303816000875af1925050508015611444575060408051601f3d908101601f191682"
        "019092526114419181019061211e565b60015b6114a1573d808015611472576040519150601f19603f3d011682016040523d82523d6000"
        "602084013e611477565b606091505b5080516000036114995760405162461bcd60e51b815260040161050f90612038565b805181602001"
        "fd5b6001600160e01b031916630a85bd0160e11b149050610e99565b506001949350505050565b6060816000036114f057505060408051"
        "80820190915260048152630307830360e41b602082015290565b8160005b811561151357806115048161208a565b915050600882901c91"
        "506114f4565b610e998482611600565b604080516002808252818301909252606091906004908490600090846020820181803683370190"
        "50509050835b8360ff168160ff1610156115c357828160ff168151811061156d5761156d611ed5565b01602001516001600160f81b0319"
        "1682611587878461213b565b60ff168151811061159a5761159a611ed5565b60200101906001600160f81b031916908160001a90535080"
        "6115bb81611f26565b91505061154a565b5095945050505050565b6115d7838361179c565b6115e460008484846113c5565b6105b05760"
        "405162461bcd60e51b815260040161050f90612038565b6060600061160f83600261215e565b61161a906002612020565b67ffffffffff"
        "ffffff811115611632576116326119e7565b6040519080825280601f01601f19166020018201604052801561165c576020820181803683"
        "370190505b509050600360fc1b8160008151811061167757611677611ed5565b60200101906001600160f81b031916908160001a905350"
        "600f60fb1b816001815181106116a6576116a6611ed5565b60200101906001600160f81b031916908160001a90535060006116ca846002"
        "61215e565b6116d5906001612020565b90505b600181111561174d576f181899199a1a9b1b9c1cb0b131b232b360811b85600f16601081"
        "1061170957611709611ed5565b1a60f81b82828151811061171f5761171f611ed5565b60200101906001600160f81b031916908160001a"
        "90535060049490941c936117468161217d565b90506116d8565b5083156108925760405162461bcd60e51b815260206004820181905260"
        "248201527f537472696e67733a20686578206c656e67746820696e73756666696369656e74604482015260640161050f565b6001600160"
        "a01b0382166117f25760405162461bcd60e51b815260206004820181905260248201527f4552433732313a206d696e7420746f20746865"
        "207a65726f2061646472657373604482015260640161050f565b6000818152600260205260409020546001600160a01b03161561185757"
        "60405162461bcd60e51b815260206004820152601c60248201527f4552433732313a20746f6b656e20616c7265616479206d696e746564"
        "00000000604482015260640161050f565b6118636000838361136e565b6001600160a01b03821660009081526003602052604081208054"
        "6001929061188c908490612020565b909155505060008181526002602052604080822080546001600160a01b0319166001600160a01b03"
        "861690811790915590518392907fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef908290a45050565b60"
        "01600160e01b03198116811461091c57600080fd5b60006020828403121561191257600080fd5b8135610892816118ea565b60005b8381"
        "1015611938578181015183820152602001611920565b8381111561081f5750506000910152565b60008151808452611961816020860160"
        "20860161191d565b601f01601f19169290920160200192915050565b6020815260006108926020830184611949565b6000602082840312"
        "1561199a57600080fd5b5035919050565b80356001600160a01b03811681146119b857600080fd5b919050565b60008060408385031215"
        "6119d057600080fd5b6119d9836119a1565b946020939093013593505050565b634e487b7160e01b600052604160045260246000fd5b60"
        "40805190810167ffffffffffffffff81118282101715611a2057611a206119e7565b60405290565b600082601f830112611a3757600080"
        "fd5b611a3f6119fd565b806040840185811115611a5157600080fd5b845b81811015611a6b578035845260209384019301611a53565b50"
        "9095945050505050565b600082601f830112611a8757600080fd5b611a8f6119fd565b806080840185811115611aa157600080fd5b845b"
        "81811015611a6b57611ab58782611a26565b8452602090930192604001611aa3565b600082601f830112611ad657600080fd5b60405161"
        "0d2080820182811067ffffffffffffffff82111715611afb57611afb6119e7565b60405283018185821115611b0e57600080fd5b845b82"
        "811015611b28578035825260209182019101611b10565b509195945050505050565b6000806000806000610e408688031215611b4c5760"
        "0080fd5b611b55866119a1565b9450611b648760208801611a26565b9350611b738760608801611a76565b9250611b828760e08801611a"
        "26565b9150611b92876101208801611ac5565b90509295509295909350565b600080600060608486031215611bb357600080fd5b611bbc"
        "846119a1565b9250611bca602085016119a1565b9150604084013590509250925092565b600060208284031215611bec57600080fd5b61"
        "0892826119a1565b600067ffffffffffffffff80841115611c1057611c106119e7565b604051601f8501601f19908116603f0116810190"
        "8282118183101715611c3857611c386119e7565b81604052809350858152868686011115611c5157600080fd5b85856020830137600060"
        "2087830101525050509392505050565b600060208284031215611c7d57600080fd5b813567ffffffffffffffff811115611c9457600080"
        "fd5b8201601f81018413611ca557600080fd5b610e9984823560208401611bf5565b801515811461091c57600080fd5b60008060408385"
        "031215611cd557600080fd5b611cde836119a1565b91506020830135611cee81611cb4565b809150509250929050565b60008060008060"
        "808587031215611d0f57600080fd5b611d18856119a1565b9350611d26602086016119a1565b925060408501359150606085013567ffff"
        "ffffffffffff811115611d4957600080fd5b8501601f81018713611d5a57600080fd5b611d6987823560208401611bf5565b9150509295"
        "9194509250565b600080600080610e208587031215611d8c57600080fd5b611d968686611a26565b9350611da58660408701611a76565b"
        "9250611db48660c08701611a26565b9150611dc4866101008701611ac5565b905092959194509250565b60008060408385031215611de2"
        "57600080fd5b611deb836119a1565b9150611df9602084016119a1565b90509250929050565b600181811c90821680611e1657607f8216"
        "91505b602082108103611e3657634e487b7160e01b600052602260045260246000fd5b50919050565b6020808252602e908201527f4552"
        "433732313a2063616c6c6572206973206e6f7420746f6b656e206f776e6560408201526d1c881b9bdc88185c1c1c9bdd995960921b6060"
        "82015260800190565b60008351611e9c81846020880161191d565b835190830190611eb081836020880161191d565b0194935050505056"
        "5b60008251611ecb81846020870161191d565b9190910192915050565b634e487b7160e01b600052603260045260246000fd5b634e487b"
        "7160e01b600052601160045260246000fd5b600060ff821660ff84168060ff03821115611f1e57611f1e611eeb565b019392505050565b"
        "600060ff821660ff8103611f3c57611f3c611eeb565b60010192915050565b8060005b600281101561081f578151845260209384019390"
        "910190600101611f49565b610e208101611f778287611f45565b60408083018660005b6002811015611fa757611f94838351611f45565b"
        "9183019160209190910190600101611f80565b50505050611fb860c0830185611f45565b61010082018360005b6069811015611fe05781"
        "51835260209283019290910190600101611fc1565b50505095945050505050565b600060208284031215611ffe57600080fd5b81516108"
        "9281611cb4565b60008282101561201b5761201b611eeb565b500390565b6000821982111561203357612033611eeb565b500190565b60"
        "208082526032908201527f4552433732313a207472616e7366657220746f206e6f6e20455243373231526560408201527131b2b4bb32b9"
        "1034b6b83632b6b2b73a32b960711b606082015260800190565b60006001820161209c5761209c611eeb565b5060010190565b634e487b"
        "7160e01b600052601260045260246000fd5b6000826120c8576120c86120a3565b500490565b6000826120dc576120dc6120a3565b5006"
        "90565b6001600160a01b038581168252841660208201526040810183905260806060820181905260009061211490830184611949565b96"
        "95505050505050565b60006020828403121561213057600080fd5b8151610892816118ea565b600060ff821660ff841680821015612155"
        "57612155611eeb565b90039392505050565b600081600019048311821515161561217857612178611eeb565b500290565b60008161218c"
        "5761218c611eeb565b50600019019056fea2646970667358221220291bb756f8e522344ab04c3654d52559906dcc8f319583d1b1377a83"
        "6b30caaa64736f6c634300080e0033")};
    EXPECT_CALL(transaction, get_one(db::table::kCodeName, silkworm::ByteView{kCodeKey2}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kCodeValue2;
        }));

    // TransactionDatabase::get_one: TABLE Code > 1
    static Bytes kCodeKey3{*silkworm::from_hex("03bd926f4f7e58b476046cb0e894971c99a49e79d41374a6339201c7b79655e4")};
    static Bytes kCodeValue3{*silkworm::from_hex(
        "608060405234801561001057600080fd5b506004361061002b5760003560e01c8063cc48241e14610030575b600080fd5b61004361003e"
        "366004613ff4565b610057565b604051901515815260200160405180910390f35b6000610061613e07565b604080518082018252875181"
        "52602080890151818301529083528151608081018352875151818401908152885183015160608301528152825180840184528883018051"
        "51825251830151818401528183015283820152815180830183528651815286820151818301528383015281516069808252610d40820190"
        "935260009290918201610d208036833701905050905060005b60698110156101435784816069811061010f5761010f6140d2565b602002"
        "0151828281518110610126576101266140d2565b60209081029190910101528061013b816140fe565b9150506100f4565b5061014e8183"
        "61016f565b60000361016057600192505050610167565b6000925050505b949350505050565b60007f30644e72e131a029b85045b68181"
        "585d2833e84879b9709143e1f593f00000018161019b610366565b9050806080015151855160016101b19190614117565b146101f85760"
        "405162461bcd60e51b81526020600482015260126024820152711d995c9a599a595c8b5898590b5a5b9c1d5d60721b6044820152606401"
        "5b60405180910390fd5b604080518082019091526000808252602082018190525b86518110156102e9578387828151811061022b576102"
        "2b6140d2565b6020026020010151106102805760405162461bcd60e51b815260206004820152601f60248201527f76657269666965722d"
        "6774652d736e61726b2d7363616c61722d6669656c640060448201526064016101ef565b6102d5826102d0856080015184600161029991"
        "90614117565b815181106102a9576102a96140d2565b60200260200101518a85815181106102c3576102c36140d2565b60200260200101"
        "51613756565b6137ec565b9150806102e1816140fe565b91505061020f565b506103128183608001516000815181106103055761030561"
        "40d2565b60200260200101516137ec565b90506103486103248660000151613885565b8660200151846000015185602001518587604001"
        "518b604001518960600151613924565b6103585760019350505050610360565b600093505050505b92915050565b61036e613e58565b60"
        "40805180820182527f2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e281527f14bedd503c37ceb061d8ec"
        "60209fe345ce89830a19230301f076caff004d19266020808301919091529083528151608080820184527f0967032fcbf776d1afc985f8"
        "8877f182d38480a653f2decaa9794cbc3bf3060c8285019081527f0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7f"
        "c13db7ab606080850191909152908352845180860186527f304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346"
        "a781527f1739c1b1a457a8c7313123d24d2f9192f896b7c63eea05a9d57f06547ad0cec881860152838501528584019290925283518082"
        "0185527f198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c28186019081527f1800deef121f1e76426a0066"
        "5e5c4479674322d4f75edadd46debd5cd992f6ed828501528152845180860186527f090689d0585ff075ec9e99ad690c3395bc4b313370"
        "b38ef355acdadcd122975b81527f12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa818601528185015285"
        "850152835190810184527f1bdb443ce61ebcf93daed4215a57e1cec90ca64973023e31197a112e8cee72f68185019081527f117e26c423"
        "5f42625b3404f2973059814ff260dba7176d7aae910f493a8e1fb5828401528152835180850185527f196e247a12f580e36894f256f0c1"
        "22393489b4c213b3e913250feee806ca45ff81527f2fedff4e4bbcbf9f1c56e28a060d50eef5f54e2aab897f6b465acd2ed005ae918185"
        "015281840152908401528151606a808252610d608201909352919082015b60408051808201909152600080825260208201528152602001"
        "906001900390816105ea57505060808201908152604080518082019091527f19137c5ee0d446f9ea37253e4156733982a9be1f2653ea4a"
        "a7c8956a0956578081527f0f326406aae01537155ac859c98190e48b83c1aef1a7a08bf7e36bc74dbe234f602082015290518051600090"
        "61067d5761067d6140d2565b602002602001018190525060405180604001604052807f1fa369834e93a543e48018f23161413025b0f103"
        "b6926a2e5a35a9f1478247fa81526020017f2de2f34cbb62bf6487a688851201f77c66088400f757fc26bc131d58c809d9508152508160"
        "8001516001815181106106f4576106f46140d2565b602002602001018190525060405180604001604052807f0e2d72fc1b164337f438ae"
        "281885a295073608daf894b98d2618e05e4880898481526020017f07685cebbe00a839a825e3862cde3abbe4ba1dc6a707b583edff805e"
        "f7598d85815250816080015160028151811061076b5761076b6140d2565b602002602001018190525060405180604001604052807f2bb7"
        "979b54c7e71567b5835795335437de2f9b8415052e986823e4aaa402fc8281526020017f243f0ae8ccea02f678f9be14a3122de826c1fa"
        "231f7df498782682b23ae5eb9f81525081608001516003815181106107e2576107e26140d2565b60200260200101819052506040518060"
        "4001604052807f254fc64d6ccb25f2314002c509bf6f75aed8627026806124e8d44143aea852e681526020017f241c770f8ec21d720cd9"
        "d9c1fce748992f1703bd91f1a35c177936313000fa318152508160800151600481518110610859576108596140d2565b60200260200101"
        "8190525060405180604001604052807f0dd5dde865e9b86969d20f761f5409a1032fbbccd9176fcde34b1eb9a8d3e49281526020017f2e"
        "51c8cd7576f63297058c456288db24df973928779e480f52a6b3415850577b81525081608001516005815181106108d0576108d06140d2"
        "565b602002602001018190525060405180604001604052807f0b4caca48320d0875e6bab918b3e88e844303bbe096c31fb58c0d0674863"
        "de5781526020017f247752e86a99f5e7aded5b30b8437cae16b0ec93bc0cd888cc9e278904a4d8c1815250816080015160068151811061"
        "0947576109476140d2565b602002602001018190525060405180604001604052807f1c0a57937775a34e31c5b376dfe7ffb040729d8731"
        "d840de31d091b90163b56881526020017f0d6222e78fc275cb304c2dca18b512a27c5a41e2e5412be816d8bf43354b1182815250816080"
        "01516007815181106109be576109be6140d2565b602002602001018190525060405180604001604052807f16dce98793314504444e19ec"
        "d87aafd1bb904a88fc5185adaf22e81f80cf8e5881526020017f056ea26135ef60e1535db7afadc8a3590d9306836b1e0b3eb3563823df"
        "fe2d0d8152508160800151600881518110610a3557610a356140d2565b602002602001018190525060405180604001604052807f087118"
        "991e9cf9d7ab012853fe3486cc5141c627b11649c7cb498a8045c5b80381526020017f273f5c6cd47c3e979395300ec417458be7bb9f6b"
        "98c82066e989bc643aa152698152508160800151600981518110610aac57610aac6140d2565b6020026020010181905250604051806040"
        "01604052807f1f1dfced4cc3685e5ab710758ae81b010e4aef0022093cef1539a49089e2ea2381526020017f2f841e747be405a491a506"
        "7bc9c54d4277ce58d43a5387dbe8c900702ac3b6178152508160800151600a81518110610b2357610b236140d2565b6020026020010181"
        "90525060405180604001604052807f2a0fca4abbbca4455ee5638943266bccc4273fc8fc3995d5dfd05500744ee4ce81526020017f186e"
        "a9e13af4b6e47ec8d4b2c92ff4a8f150f59daad22cf8ab03cad017bc83458152508160800151600b81518110610b9a57610b9a6140d256"
        "5b602002602001018190525060405180604001604052807f24c3727cddb21774a473b3cf04b47ba2c67aed9defed06045e032dcbff5ffb"
        "c181526020017f2dc3650ecbc98e21e764b6c211cb2f8d755aabf7d4675116169ff3e69fbd07d58152508160800151600c81518110610c"
        "1157610c116140d2565b602002602001018190525060405180604001604052807f04641de8ea796e54982eb5baebc5454f61ca572acd42"
        "7fa3b40d122dbc25caf381526020017f2cbd22d3682466e1553a2670adcd9e5bb9baca49c13ebd70a194d8c1d2a5e62181525081608001"
        "51600d81518110610c8857610c886140d2565b602002602001018190525060405180604001604052807f23d3f147b20b030c2a4908fb6c"
        "16453d56d17ae13ae718b4ef0865fc94513a2281526020017f06642fa085c164fef38bc00ad6246cc0dbee1c1e0364863e6918973f6cc8"
        "cb928152508160800151600e81518110610cff57610cff6140d2565b602002602001018190525060405180604001604052807f2f691c06"
        "a50cbc3eeef3fedd39111695246442219681ac4d52169526565b291581526020017f226a29208e1e20be8a788065f6062e203ab32bdd26"
        "b05334af2507880072bf068152508160800151600f81518110610d7657610d766140d2565b602002602001018190525060405180604001"
        "604052807f1632c1f52eabdc5b8fddcacc12fbdfeaf6adb5a26dda93084acf25ccc64892b881526020017f16830dabdc03dbe4d71e2d03"
        "4d0cd0ff6ed8169d476eeec2b0b5e008b6100d9b8152508160800151601081518110610ded57610ded6140d2565b602002602001018190"
        "525060405180604001604052807f2eb1f1b8c0eeb6890893b4886700e5177ca24fc4946cc31b7b4835e95d77633581526020017f1a2063"
        "e295f08ec3a5e91f8db1a7adad81aca8825564f812bfa1b03886dde6dc8152508160800151601181518110610e6457610e646140d2565b"
        "602002602001018190525060405180604001604052807f02756c358cea93b4c72f5d5dec994e2a4c0829271878f90723d552f1bc107359"
        "81526020017f1bf732ecf2e4ada022df3e61f0d5bc5907d8f633c383f872416c3f31903ad38d8152508160800151601281518110610edb"
        "57610edb6140d2565b602002602001018190525060405180604001604052807f079ecfd71d11ac7cbed590c809df5a7dbb4b90deec1a91"
        "cb4ef6bc3fd454b1a781526020017f0a4645b7f08a9636bf9111fb4870eca3f8cec912db2abb447128d518f8e502bc8152508160800151"
        "601381518110610f5257610f526140d2565b602002602001018190525060405180604001604052807f2ac8ba45b313107691eb48153d7a"
        "0a6c83d0f041684f9b6126cd7b09a750f42381526020017f16a0649e208f81968e82eef7e7d4cd71d4a9d10d3f91d5ee1f221fc3f91b20"
        "718152508160800151601481518110610fc957610fc96140d2565b602002602001018190525060405180604001604052807f0c65550bce"
        "eea7e405244d6f99be6adf5b694562fefc9aea8e2e396a71adef0481526020017f1f9d677a17d032fe197f0cef5b2b957651a85f37c3b3"
        "0af1ae3a8e7ddb8f91768152508160800151601581518110611040576110406140d2565b60200260200101819052506040518060400160"
        "4052807f1e6e8c7df025963d39e0567c893636773c055816d751572b8d529d0df62a892c81526020017f2c2bc9a81191aee3a4b851c5f1"
        "7f8563089705cb5756223a7e26fde50e69799481525081608001516016815181106110b7576110b76140d2565b60200260200101819052"
        "5060405180604001604052807f2d7088761d6c87fdd83f5978fe4e37d3953a62882e71281e3abfba3dc7d9480981526020017f01f04214"
        "482446b0e136f3b028dba1b2040f324cf288ebbb886ffd2720a75727815250816080015160178151811061112e5761112e6140d2565b60"
        "2002602001018190525060405180604001604052807f103eba1875783df4450a7ca5ad7c0638a19f3cd328a1d47207687dc7f86c70cc81"
        "526020017f068ab8d05c4c4b79afd73be38bb5a7d2aba1ebc14c7d085b3bc4db9128dd4df981525081608001516018815181106111a557"
        "6111a56140d2565b602002602001018190525060405180604001604052807f2c578972c1b33ffe47068beb826ea56807b8cca014fc19a3"
        "33ae3f7dfad1e3d781526020017f1b43dd6c68334115a787a3d081982da384fc72b2156c9febbe3ba213cd3f8bd6815250816080015160"
        "198151811061121c5761121c6140d2565b602002602001018190525060405180604001604052807f1a32d855c5c83f01ebb93fb41ee5ae"
        "8e332a0b48e72a2dcb80a321f38db1384e81526020017f1bf984aa135a3e04e2bfe2c6038e43ac0a46afed390c385da40c3f2f81211914"
        "8152508160800151601a81518110611293576112936140d2565b602002602001018190525060405180604001604052807f1128411292d3"
        "197b9d62fe003b1dd929a2147921e698ea5f4ce7d81fee7eb69f81526020017f08c22bd9e5651e5a1ccb0594a56771b4d40fb7aa97ba32"
        "e3572a91a56bd820908152508160800151601b8151811061130a5761130a6140d2565b6020026020010181905250604051806040016040"
        "52807f2e7e9988ecd1cc979274982672fc859bd3e1691ac5f4fa23d16054f096bfea4281526020017e5d112624a7da3803e567f29f4020"
        "417f9e38976338b1b23f5bae542b875b328152508160800151601c81518110611380576113806140d2565b602002602001018190525060"
        "405180604001604052807f017381294aa4ca6b83a3dd87db62c59e3e44be624b3d52c2a5205016c152ddab81526020017f08653dfd77b6"
        "d95970f7af5f3fc31eb30983a7c622f35e452d8771dd5426685c8152508160800151601d815181106113f7576113f76140d2565b602002"
        "602001018190525060405180604001604052807f0186ac5e4381b013bf05328833c1610ef06b9057412891fe3cfe2cda8d4c89a7815260"
        "20017f23d2b1e536a61030aab005df050cff8118306e2ce9a2e9ee5ef667f612e51bc38152508160800151601e8151811061146e576114"
        "6e6140d2565b602002602001018190525060405180604001604052807f014fe1c7c6899fdb6eb0e11e7e1584452e6b984bb96ec8ad1917"
        "f71ca1c6d88a81526020017f1ea976e77c57b20763af5ee4914f6534b8c653e05dcaa28fae66f932236b69718152508160800151601f81"
        "5181106114e5576114e56140d2565b602002602001018190525060405180604001604052807f12a98eca9e1e25aac249edb9e90de7c95b"
        "55704a5ede0368bf040292043498c481526020017f037154296da31f7d4edbb12a14ca3756d07bf23310e3deeb63313a81660620cc8152"
        "50816080015160208151811061155c5761155c6140d2565b602002602001018190525060405180604001604052807f2974bbeeebfcbadf"
        "e193507f1f933c92de0b6d2db70bdcc4125396e5780c622481526020017f0e3d643ca61c0a520bad5cbb9a2433d670278c137c28503a67"
        "38195d5f99b6f781525081608001516021815181106115d3576115d36140d2565b60200260200101819052506040518060400160405280"
        "7f0ca3f27bc61e1bc34d6df76bbc629014cec0af843aeaa3539b5de41960d225c281526020017f151ef4a35073a33dae1538037da7b307"
        "99537c7856b624bf84f02d26cdd58a91815250816080015160228151811061164a5761164a6140d2565b60200260200101819052506040"
        "5180604001604052807f1222c05db717e1e1a34bc0929372fbdb4792613b547c89a48219e6151d5bc86281526020017f05b52ba1e516ef"
        "277f19376d08b8fc45646a5b4128071acffee792b82719df2a81525081608001516023815181106116c1576116c16140d2565b60200260"
        "2001018190525060405180604001604052807f1e19d9fc9cfd39c2f9e730316eae10f0da927ed7fa691a95bb21cdca192a020681526020"
        "017f1ecd65316549ae14314b26ea4e25a7d9b09def5c3eda4161e6f3c8a58c76df73815250816080015160248151811061173857611738"
        "6140d2565b602002602001018190525060405180604001604052807f0149086ae620084e95ebe4dc2dbda8b4519e54c8676592decb6d72"
        "6552cda5a981526020017f1da012be479ec7b7c08ece364257aceb267f490c10b950a4658a0dedc397a914815250816080015160258151"
        "81106117af576117af6140d2565b602002602001018190525060405180604001604052807f1b5e075710ac57bc5cf37eda2cbf5052ae20"
        "25e276b7eb8884a78173acb6862c81526020017f1b301f57d2c3858a64af37e76f491f4d2bc58cf3f2141bfb90640928a6cd1995815250"
        "8160800151602681518110611826576118266140d2565b602002602001018190525060405180604001604052807f2883078584d74f0e0a"
        "6e6271dc6958099f6216f852e9e7f6a83ed10459def6ef81526020017f036cc63312152e733f0afd894b2d7a2ca174719f17472392e23a"
        "8acea273f1cc815250816080015160278151811061189d5761189d6140d2565b602002602001018190525060405180604001604052807f"
        "15da4ed1e91b8c029b167f50ac83ca6888fe7268057fc374f9cb326e3dca237281526020017f1995971f33abf5718c4dff07aacc75f09b"
        "3f87493e7cff6bfdd0b3544b8763358152508160800151602881518110611914576119146140d2565b6020026020010181905250604051"
        "80604001604052807f08808fe7f5275c98eb860ef95ff6fa4803d75a624d06e1cd31a14cd6928c91e481526020017f1d8cd0dcb57056b4"
        "7303634b4caedb3ad39ca92a74e441adef834f06c676ae95815250816080015160298151811061198b5761198b6140d2565b6020026020"
        "01018190525060405180604001604052807f05c2cfdd75c80e5239ef66f69adad46face8bf437dd51bd9b5ad25ac3d8fa3ec8152602001"
        "7f0c0112c29910fcb9451c808da091d412f0c110b664e487cbc2f9f906dbd873b28152508160800151602a81518110611a0257611a0261"
        "40d2565b602002602001018190525060405180604001604052807f10062809efad68bd1944c9580504b0135381174fed88688c6c1e6a92"
        "ef43b28481526020017f0b39552c346e9b7c8c97dcfc45b5f8fd110461e9e688fc25aac4e2073a4c84698152508160800151602b815181"
        "10611a7957611a796140d2565b602002602001018190525060405180604001604052807f13db0dd3ad6b769d4a81f3eadf06f175d86423"
        "4446ca88696ecf80dff158b8f581526020017f2b8412a6ee92f787c0418093e7b3b031bbeac176579ec6f51192e7b857acf46a81525081"
        "60800151602c81518110611af057611af06140d2565b602002602001018190525060405180604001604052807f0eb0766077c4dc40d76d"
        "a9258f7c94abb334ff90e827f24cce6803a72c8d566781526020017f2a1e63e8a392e18ba8bde4d0e92fa767be50d296cfc7079bac8d83"
        "d8449649268152508160800151602d81518110611b6757611b676140d2565b602002602001018190525060405180604001604052807f1f"
        "16e8d41f368b0f015b527dc606fa23e8ed40d822a6b1492a340c6b2be66d0a81526020017f1b214be87354bceac275dbe1cee7111c24c6"
        "7e72309a7b01dc3ee5b2d9f863fd8152508160800151602e81518110611bde57611bde6140d2565b602002602001018190525060405180"
        "604001604052807f1ec1c28b85f8a70846b368b161d6d4be13e43a28fa8326039f5af809d998b51b81526020017f136cc077d58dbcc9c5"
        "79e2cb90a7a75134cc8a9c3f1e2440b9cc82cba195a4c48152508160800151602f81518110611c5557611c556140d2565b602002602001"
        "018190525060405180604001604052807f1252284c661b8d15017034247ffd6e0e4a9c9821063b12d6b6c824d44d3d120981526020017f"
        "21bef77b2cf4a5a0a693c55c15699b6e4fe144e5dee61c87dc3a241a8066d7f38152508160800151603081518110611ccc57611ccc6140"
        "d2565b602002602001018190525060405180604001604052807f2bfc07343ce336a0f6df74a1a7779348fde2588eda6f9867430a7db13f"
        "51700481526020017f1b4fe59b1634a69b86d5e89de4f85ccf78c5a2f488e5aa471ecf79b8aae614f08152508160800151603181518110"
        "611d4357611d436140d2565b602002602001018190525060405180604001604052807f140dc93c0bdd54987b3be541d5505331ef5e4656"
        "602ce9809cad9dd9e53298c381526020017ee0bf22fa82aaac077fba4c951a4cb4ffee29aee5f62f6b1022dc8a94db2381815250816080"
        "0151603281518110611db957611db96140d2565b602002602001018190525060405180604001604052807f18888e0714d4cb0a1320b119"
        "cae533eb2406ea4a81d66b5789110d221084ed3e81526020017f04fe8092c81bab6f3f17797a4fecb450f6477a69b464334527c07b60df"
        "da90748152508160800151603381518110611e3057611e306140d2565b602002602001018190525060405180604001604052807f28d2b9"
        "acfca0e1a5570c6bf92ac59133ec7ba981218916a7ea23d8cee947adff81526020017f0d030a87005f28e56891c60bf7f3cd87262658c1"
        "4074e68d5a3850fc5fcadd578152508160800151603481518110611ea757611ea76140d2565b6020026020010181905250604051806040"
        "01604052807f0aa313883d3d2794a277c3deeeed3742e6995654db70aea1e10b45f6699b63c381526020017f1de8ce41a7f72c69a6ce5d"
        "bbfbaab36fc3ac5739cf8d89dad1009ce4c44908fa8152508160800151603581518110611f1e57611f1e6140d2565b6020026020010181"
        "90525060405180604001604052807f0fe6d78753897394becd474a5e6fdb46411d8d8902d93a0765b879d1a957316381526020017e3f2b"
        "7944e36241ffed15a52caf0e11f9893f57df749234c0ce228eb4393e938152508160800151603681518110611f9457611f946140d2565b"
        "602002602001018190525060405180604001604052807f165a0cc81f46dd2edd1f1e77eed7692fae7310bb4d1de5d53c52b9a230ba5d43"
        "81526020017f2f79376822794b12230583fe44e2df6350dd7733f057e9da3d9576fe4fe8e70a815250816080015160378151811061200b"
        "5761200b6140d2565b602002602001018190525060405180604001604052807f1d068a7648dca4c6b1c7ef121b32ad721ade8e56a4859a"
        "1211c72b5a2b54d00481526020017f11e9784da14190569cc3b861f2b6d7191ba81bcd4b8bc9c0bf57a1ae500e944f8152508160800151"
        "603881518110612082576120826140d2565b602002602001018190525060405180604001604052807f1e657e06d14beed19f96368578a3"
        "bad8c880d7ceac68013994a93034fa9fbf9b81526020017f1986cbb11ce095db456b9163b2948d8256e149c7d475c5e559fe99ec536a77"
        "e581525081608001516039815181106120f9576120f96140d2565b602002602001018190525060405180604001604052807f136b51b813"
        "af292886f9e8bbfe2b51daf09432b60c111ae0a1607b2264db874381526020017f15619829c4c82e47edd79a8a211c312476d674cc62e3"
        "2fcfebda76f1d3fca5358152508160800151603a81518110612170576121706140d2565b60200260200101819052506040518060400160"
        "4052807f1b63e90c16e62b1af33707f8366e797866f97957f735c5befe5998aceefbbe0581526020017f01c2a0477ad077eae421875dfe"
        "805d91626af3d8d573485ba1885548403f5b4c8152508160800151603b815181106121e7576121e76140d2565b60200260200101819052"
        "5060405180604001604052807f1b0a318065817b48054959f62a7fa21a8197ce13f65b39856a3b917e6379b9e881526020017f1a66a335"
        "018d4c6263c7fe84c3fa661c45bb1595ace18404591fb321c9e0be1e8152508160800151603c8151811061225e5761225e6140d2565b60"
        "2002602001018190525060405180604001604052807f278fe6e5e9c75ad4f2eaaf65b5d2f9f5d8ecf8636b5d034593dccc04046a53c381"
        "526020017f2087634b4f288a892897792acd519e3ab3b82ca02e439271456456f6c0ee698a8152508160800151603d815181106122d557"
        "6122d56140d2565b602002602001018190525060405180604001604052807f16876a3235e6200b843ae57103947d0016c6cb640a4eec5c"
        "f2d23d407adc352c81526020017f29a188406c67332d2e7cbea8dc54aa680a93ccf9f13ba5ca73ec1fe7b0f1e399815250816080015160"
        "3e8151811061234c5761234c6140d2565b602002602001018190525060405180604001604052807f178fef0947857d3725e0d2434b3251"
        "305724a60de963905cd1838130fbaed5ea81526020017f236a8c908c2081330c6554195a870aa8cdd07dece6549c7c2cee4dafe9c7562a"
        "8152508160800151603f815181106123c3576123c36140d2565b602002602001018190525060405180604001604052807f192c29f425b0"
        "dcb1324fdc15414e5bb6bd06efe196b03c8565aa9702020d0b2881526020017f08ddf134cc72d675c08c6bd828973cf7cb6689b62ffe64"
        "b37e409817ead32b18815250816080015160408151811061243a5761243a6140d2565b6020026020010181905250604051806040016040"
        "52807f18382569a669107072ab80584314c9ab6f83ea4f555ac3ae6f1164f57d3e63a181526020017f28a252efe9a70aea3745f60c704f"
        "497be3764c59b82bd3183944b120cdf003c281525081608001516041815181106124b1576124b16140d2565b6020026020010181905250"
        "60405180604001604052807f2a94d6960b8faba4b4b33f3f391a0e28afb09cfb18492f2cb442e9bf767787c081526020017f1cc4c58b52"
        "32d232553202f461f0a896d0132a66d6ee42c84ad7aa0af68d7b888152508160800151604281518110612528576125286140d2565b6020"
        "02602001018190525060405180604001604052807f144c31f626f16e98e7263de5a70d6d1f268f9e800a98f83be9446cef11b52db88152"
        "6020017f175f805e09adaa3ce8019d27f5d31d0d38f2ddd7fd3ba3dd9e07620e8bf41608815250816080015160438151811061259f5761"
        "259f6140d2565b602002602001018190525060405180604001604052807f2d9f3b5f1d6300415ed21dc3020e63d88cd121e9abf0679679"
        "295366711d143381526020017f1f231d0120a508a45676ced59a60124bbd4424209ad3ea2f684db7de5d1a8ea181525081608001516044"
        "81518110612616576126166140d2565b602002602001018190525060405180604001604052807f0a7663303944ecfd34f96ba5e1a13aac"
        "f3367232dd8651edf35b51292211ec8681526020017f07c07b82b2ad82dd9770a2b1c1bd95950352a9773548e46aae1256736efad28581"
        "5250816080015160458151811061268d5761268d6140d2565b602002602001018190525060405180604001604052807f22fc6e3dcf8ea1"
        "98c7722ad6bce5b0893e0c7afbe69c32bc2fb874223641546881526020017f1ed1b7ed2e8ea7222174142ac23fcf9112fb812ea62bc91e"
        "0b02646e2a791b018152508160800151604681518110612704576127046140d2565b602002602001018190525060405180604001604052"
        "807f1194d827f188bfa5739f30ba7cba094e9aafb2f0172324aa6a9b6905462b9ceb81526020017f1e749462071dc8484e39c4f9b01f7c"
        "230274c43c419d243f5e83900884473b22815250816080015160478151811061277b5761277b6140d2565b602002602001018190525060"
        "405180604001604052807f2bbc9123740e0816bd8b419976abd81791e323e269b468916d6288e72402524981526020017f0716da8a0508"
        "492455a86f88cc00de7f2e93861283d26c66a1fb524a581a140681525081608001516048815181106127f2576127f26140d2565b602002"
        "602001018190525060405180604001604052807f137507ca0359a18b19c1fefdf32b3c871973221d3a295b2695ebb8bf5f999d59815260"
        "20017f2d19a5ff84f42d72b978cc93fa016a7b7ac41bcdf400211b22ea44a4baeab4058152508160800151604981518110612869576128"
        "696140d2565b602002602001018190525060405180604001604052807f1a905b64094ffb8aa77bfc45a81a92a6a9a670c5525f914ccbdf"
        "e7b4726c647181526020017f2ac1ff1570e1ea9bbb747980079be2ff5ff47de99533bf78c98cc91d2722e1268152508160800151604a81"
        "5181106128e0576128e06140d2565b602002602001018190525060405180604001604052807f21418d8a8cfd1038ad8ce619b869c9aeee"
        "77522e79a7f634e0854eddd01dc05781526020017f2f48b4bd4deefc45cc0a76780f05b2f097cc403531e46c9cc33b2971d63544148152"
        "508160800151604b81518110612957576129576140d2565b602002602001018190525060405180604001604052807f0e4e905bbd7cf18d"
        "35ca5697555158db8e72cb116809f6ca3707ffce6533e33d81526020017f080e9438004bde946adb282af5fa7a40fcb2909a5858a899a2"
        "3cdebb68b9c6128152508160800151604c815181106129ce576129ce6140d2565b60200260200101819052506040518060400160405280"
        "7f281660cd1c611f4e2cee2d520e09e3bdfd10e4336f5ebb650a752d8d3c42bac381526020017ec930b447b63f332e6fe9ba1f1feda513"
        "094b1c259ca97454e8fef5ba693b0d8152508160800151604d81518110612a4457612a446140d2565b6020026020010181905250604051"
        "80604001604052807f212b77cf556f0cf81226cebcff966d7c2e74810f63e134f8ddae93d213144a8e81526020017f281d4426d3ebe44d"
        "3bc39468a63f63c36f60f89352a116b3f586869b09c5437e8152508160800151604e81518110612abb57612abb6140d2565b6020026020"
        "01018190525060405180604001604052807f17555bda28f497946f1fbdb0a76c624b70f1cc4194795ad91c26be3582a2f77c8152602001"
        "7f080977cde5356a031d4937e8efddec6e4895bf71f1f2e604a7c0e5242a1444d18152508160800151604f81518110612b3257612b3261"
        "40d2565b602002602001018190525060405180604001604052807f2534e64bdc0ee685fc1e63f2370e45a5c0405cf09ccb47b985be7bdc"
        "3764df6981526020017f2b221aa101b3a27b219f27d60a52fcdd0daaa4fa22cdfa9e952af94efbee09eb81525081608001516050815181"
        "10612ba957612ba96140d2565b602002602001018190525060405180604001604052807f26f902bda6c967ed2a13dadd810f4d11866ac9"
        "4f1b4e854d051f00e3327e6e5d81526020017f29fa6d877019e1e6b35e51defc7d4a8ad4be095a29dbe60b51af558943956d0b81525081"
        "60800151605181518110612c2057612c206140d2565b602002602001018190525060405180604001604052807f084747ddf21da3680f1e"
        "71ee3982e86ac8307a2227750f8fd35c00c713c1e25e81526020017f0c9ab78efda5900ada3a1f7e304b0b5ae296652fd7e9ffe0783b5e"
        "256fa324e68152508160800151605281518110612c9757612c976140d2565b602002602001018190525060405180604001604052807f1f"
        "061ccb55609be811b8a1b5d3c03505d74a58f60841284d9bb6e63ff137a55081526020017f1ef3ed6e11412f263ec7b2b2217630f435dd"
        "4e5f513df58f69054018655e56b18152508160800151605381518110612d0e57612d0e6140d2565b602002602001018190525060405180"
        "604001604052807f2d150d9d62937553c07374668dbe5c5d3174ea63310791222e8ab1f49623414281526020017f031790ee8786e8ca93"
        "ba791f25d720a9ec43ded2276342f6cba1a6c193b9a7208152508160800151605481518110612d8557612d856140d2565b602002602001"
        "018190525060405180604001604052807f0a2ed243ab407f4d3a6bf2ff3afd79d6ca2870c54990f0c18e9c7fa9bf2353db81526020017f"
        "143066fdeb23c75dd2efcc97282a81afa725d61c1a21eeeeb675466fc55bb5f18152508160800151605581518110612dfc57612dfc6140"
        "d2565b602002602001018190525060405180604001604052807f1d7b098d250861ed410b86ecc2a21af6b7371c18562c9ba497b8bba53c"
        "08fa1081526020017f119cba78f9ed0d34484b446645dd0db97e279009496076bad0866d05543a92fd8152508160800151605681518110"
        "612e7357612e736140d2565b602002602001018190525060405180604001604052807f2a8962591c2d9098eddd95b8dfd959ca417f8588"
        "263068c3cbdec88228385bfd81526020017f1756dbd10b07b8306faa4f5ecac2344f87bde2d815741ce46b8235a077f9a7a88152508160"
        "800151605781518110612eea57612eea6140d2565b602002602001018190525060405180604001604052807f12f46d55e3f14d6c55651b"
        "fe2c6f39f175084298eadb10d6235e4692ed6ec35781526020017f0796c2a5a24e491aae28d605b06a8f3a63a657661196223839b30a8b"
        "04225f448152508160800151605881518110612f6157612f616140d2565b602002602001018190525060405180604001604052807f0db7"
        "9714e5445a69e309a4c456d9f0c70bf4465a28cb6f56de09f14bff7af73581526020017f22ad061e191d4fe4ebcec82432e564c0f75e1a"
        "618e05319a28181e0fe1ee178c8152508160800151605981518110612fd857612fd86140d2565b60200260200101819052506040518060"
        "4001604052807f18f5ec74d2e48ee81b0184be94444827b3621ec1109f8b29c18db00b4ef8767681526020017f11fe06074178b5ac1064"
        "13e6bf791844077bb45ceb15d340e94326b7eda37cde8152508160800151605a8151811061304f5761304f6140d2565b60200260200101"
        "8190525060405180604001604052807f2e825fe3540ef70f9b986e69789f04e087e66c34e9b9e0cf1dbc4363481b2c5c81526020017f17"
        "206c3706c92e657aa6add257b361345d0b04fd0a4117806f2846c554c86f548152508160800151605b815181106130c6576130c66140d2"
        "565b602002602001018190525060405180604001604052807f0d1910d9b98660a729ad69d0f3716b56b67bbdde3a1152b1a21c29f82ed9"
        "ccf381526020017f11689a8348317b3a3e11a9f66c04c4d1577446ead32479120a7817b58618247a8152508160800151605c8151811061"
        "313d5761313d6140d2565b602002602001018190525060405180604001604052807f0f0a7475c1febb613d620bb52048eddb577ee9c601"
        "3a33b69f2f5fe4dbd64fcd81526020017f2ebc18b038340a0743df5d7e34455f4aafff9219b49dfa12e4635ba0ae47d6c3815250816080"
        "0151605d815181106131b4576131b46140d2565b602002602001018190525060405180604001604052807f2aa8bf7e8875013205cc0815"
        "8bef5c5fe99dbfc0bb4acfe798d52e7db036004381526020017f0661ed4589aeb5a42b998d136bf581c2188396e7df71460a980279a564"
        "a7180a8152508160800151605e8151811061322b5761322b6140d2565b602002602001018190525060405180604001604052807f1eb7d8"
        "d21544131ffe193d1c14a2fba278ad5907fdf079549a366c998bd7e17481526020017f2f2292fc11ca07b5f85e67b4f409a475a7e3481a"
        "3d998721fa04a21343000fbf8152508160800151605f815181106132a2576132a26140d2565b6020026020010181905250604051806040"
        "01604052807f101955958fddc8638f6e939e6336495856309d20dc19e05bdb936da1caff845c81526020017f1da5d0efccffed9d0c8630"
        "b412ba3c9e229d262ce5c90a38e8bae0e90440af9e8152508160800151606081518110613319576133196140d2565b6020026020010181"
        "90525060405180604001604052807f2a975aaeab34573170905629532d6f24ede619c7722317e807231a0712cc50e481526020017f26f6"
        "df98afb68f53be06ac07610b5106de4ec830135d5e91a7a619834883e3c88152508160800151606181518110613390576133906140d256"
        "5b602002602001018190525060405180604001604052807f24eb60c7c0f81d020688d00bf93e29b2a657402c2430a2a233ee49d1d30cfb"
        "1581526020017f25746e946b1fe4c8f3113341b135085435c2b88ccd2b709be1d54db30521503a81525081608001516062815181106134"
        "07576134076140d2565b602002602001018190525060405180604001604052807f2194768ad54404355e4d16a7ded7feec7dad589e7b53"
        "16d798d0412838ce8cf581526020017f23fab978c5374203e4db5ada56f08ab356b055f6ce3e5e70e529cdca8da8659181525081608001"
        "5160638151811061347e5761347e6140d2565b602002602001018190525060405180604001604052807f03b59f535f67bcb0eedc5a5b71"
        "262ff627feef4e2c9763a72a3495898764be2e81526020017f042b4f1710f38b8de7b92a8d35d5c6ff043fe97337513c5ae59d6a20ecff"
        "45a381525081608001516064815181106134f5576134f56140d2565b602002602001018190525060405180604001604052807f168e4761"
        "1662904cbdd12d3ee5a5a5ff7f0a5cd0729bfef503043b275dda625d81526020017f08afd38c49ef879ab386012b609f7202db7c12fa33"
        "aeba754ada22e23ca90027815250816080015160658151811061356c5761356c6140d2565b602002602001018190525060405180604001"
        "604052807f0c00e59f81c9c60b9f4429e851fee78bd6ae16d56e37d485b9519a02f82068f581526020017f202888cd31c3ffa4df73decf"
        "85a1bfba64286db687d9aa66d4b733ac3c92bbae81525081608001516066815181106135e3576135e36140d2565b602002602001018190"
        "525060405180604001604052807f303be1a32910aec04fafa46ae509de1740db5094fc04edf5fa785a72c376b56181526020017f23f41a"
        "c2d22fb614c9bf334b005f178ef6b9627ac379df22a15c2f7caea97d2c815250816080015160678151811061365a5761365a6140d2565b"
        "602002602001018190525060405180604001604052807f2687719f2a7389c7d3940abd09db449b35b91ad1de12b4d5433be6516937bec5"
        "81526020017f27a2f7a657aec3a1e229727955c947452d6f6bca6b402f3f5b4742b0f06456b481525081608001516068815181106136d1"
        "576136d16140d2565b602002602001018190525060405180604001604052807f1a4a9f3384686b132314f9f3239742afe9ca77270ee19d"
        "08ae3af5a31a1526da81526020017f209ea63067973b886a6a7343f43ccad9e7d905f43ae20ace2f887350205ccb568152508160800151"
        "606981518110613748576137486140d2565b602002602001018190525090565b6040805180820190915260008082526020820152613772"
        "613ea9565b835181526020808501519082015260408101839052600060608360808460076107d05a03fa905080806137a157fe5b508061"
        "37e45760405162461bcd60e51b81526020600482015260126024820152711c185a5c9a5b99cb5b5d5b0b59985a5b195960721b60448201"
        "526064016101ef565b505092915050565b6040805180820190915260008082526020820152613808613ec7565b83518152602080850151"
        "81830152835160408301528301516060808301919091526000908360c08460066107d05a03fa9050808061384257fe5b50806137e45760"
        "405162461bcd60e51b81526020600482015260126024820152711c185a5c9a5b99cb5859190b59985a5b195960721b6044820152606401"
        "6101ef565b604080518082019091526000808252602082015281517f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c"
        "16d87cfd47901580156138cc57506020830151155b156138ec5750506040805180820190915260008082526020820152919050565b6040"
        "51806040016040528084600001518152602001828560200151613911919061412f565b61391b9084614151565b90529392505050565b60"
        "408051600480825260a08201909252600091829190816020015b6040805180820190915260008082526020820152815260200190600190"
        "03908161393f57505060408051600480825260a0820190925291925060009190602082015b613989613ee5565b81526020019060019003"
        "90816139815790505090508a826000815181106139b2576139b26140d2565b602002602001018190525088826001815181106139d15761"
        "39d16140d2565b602002602001018190525086826002815181106139f0576139f06140d2565b6020026020010181905250848260038151"
        "8110613a0f57613a0f6140d2565b60200260200101819052508981600081518110613a2e57613a2e6140d2565b60200260200101819052"
        "508781600181518110613a4d57613a4d6140d2565b60200260200101819052508581600281518110613a6c57613a6c6140d2565b602002"
        "60200101819052508381600381518110613a8b57613a8b6140d2565b6020026020010181905250613aa08282613aaf565b9b9a50505050"
        "50505050505050565b60008151835114613afb5760405162461bcd60e51b81526020600482015260166024820152751c185a5c9a5b99cb"
        "5b195b99dd1a1ccb59985a5b195960521b60448201526064016101ef565b82516000613b0a826006614168565b905060008167ffffffff"
        "ffffffff811115613b2757613b27613f41565b604051908082528060200260200182016040528015613b50578160200160208202803683"
        "370190505b50905060005b83811015613d8b57868181518110613b7057613b706140d2565b60200260200101516000015182826006613b"
        "8a9190614168565b613b95906000614117565b81518110613ba557613ba56140d2565b602002602001018181525050868181518110613b"
        "c357613bc36140d2565b60200260200101516020015182826006613bdd9190614168565b613be8906001614117565b81518110613bf857"
        "613bf86140d2565b602002602001018181525050858181518110613c1657613c166140d2565b6020908102919091010151515182613c2f"
        "836006614168565b613c3a906002614117565b81518110613c4a57613c4a6140d2565b602002602001018181525050858181518110613c"
        "6857613c686140d2565b60209081029190910181015151015182613c83836006614168565b613c8e906003614117565b81518110613c9e"
        "57613c9e6140d2565b602002602001018181525050858181518110613cbc57613cbc6140d2565b60200260200101516020015160006002"
        "8110613cda57613cda6140d2565b602002015182613ceb836006614168565b613cf6906004614117565b81518110613d0657613d066140"
        "d2565b602002602001018181525050858181518110613d2457613d246140d2565b602002602001015160200151600160028110613d4257"
        "613d426140d2565b602002015182613d53836006614168565b613d5e906005614117565b81518110613d6e57613d6e6140d2565b602090"
        "810291909101015280613d83816140fe565b915050613b56565b50613d94613f05565b6000602082602086026020860160086107d05a03"
        "fa90508080613db357fe5b5080613df95760405162461bcd60e51b81526020600482015260156024820152741c185a5c9a5b99cb5bdc18"
        "dbd9194b59985a5b1959605a1b60448201526064016101ef565b505115159695505050505050565b6040805160a0810190915260006060"
        "82018181526080830191909152815260208101613e31613ee5565b8152602001613e536040518060400160405280600081526020016000"
        "81525090565b905290565b6040805160e08101909152600060a0820181815260c0830191909152815260208101613e82613ee5565b8152"
        "602001613e8f613ee5565b8152602001613e9c613ee5565b8152602001606081525090565b604051806060016040528060039060208202"
        "80368337509192915050565b60405180608001604052806004906020820280368337509192915050565b6040518060400160405280613e"
        "f8613f23565b8152602001613e53613f23565b60405180602001604052806001906020820280368337509192915050565b604051806040"
        "01604052806002906020820280368337509192915050565b634e487b7160e01b600052604160045260246000fd5b6040805190810167ff"
        "ffffffffffffff81118282101715613f7a57613f7a613f41565b60405290565b604051610d20810167ffffffffffffffff811182821017"
        "15613f7a57613f7a613f41565b600082601f830112613fb557600080fd5b613fbd613f57565b806040840185811115613fcf57600080fd"
        "5b845b81811015613fe9578035845260209384019301613fd1565b509095945050505050565b600080600080610e208086880312156140"
        "0c57600080fd5b6140168787613fa4565b9450604087605f88011261402957600080fd5b614031613f57565b8060c089018a8111156140"
        "4357600080fd5b838a015b81811015614068576140598c82613fa4565b84526020909301928401614047565b508197506140768b82613f"
        "a4565b9650505050508661011f87011261408c57600080fd5b614094613f80565b9086019080888311156140a657600080fd5b61010088"
        "015b838110156140c45780358352602092830192016140ac565b509598949750929550505050565b634e487b7160e01b60005260326004"
        "5260246000fd5b634e487b7160e01b600052601160045260246000fd5b600060018201614110576141106140e8565b5060010190565b60"
        "00821982111561412a5761412a6140e8565b500190565b60008261414c57634e487b7160e01b600052601260045260246000fd5b500690"
        "565b600082821015614163576141636140e8565b500390565b6000816000190483118215151615614182576141826140e8565b50029056"
        "fea2646970667358221220acd624e98ff105fa9cd682629b3baed16264e41a960e042760c0455def3124a564736f6c634300080e003"
        "3")};
    EXPECT_CALL(transaction, get_one(db::table::kCodeName, silkworm::ByteView{kCodeKey3}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kCodeValue3;
        }));

    // TransactionDatabase::get_one: TABLE Code > 1
    static Bytes kCodeKey4{*silkworm::from_hex("9508ecbc07caa265610cf91425373bd99e31076c88d2b8957e07c64d147645c6")};
    static Bytes kCodeValue4{*silkworm::from_hex(
        "6080604052600436106100555760003560e01c8063439fab911461005a578063772f71281461007c5780637f63f6181461009c57806388"
        "2f6b96146100c2578063ae1f6aaf146100e2578063f5f151681461011a575b600080fd5b34801561006657600080fd5b5061007a610075"
        "366004610b3e565b61013a565b005b34801561008857600080fd5b5061007a610097366004610bf0565b6103a3565b6100af6100aa3660"
        "04610c79565b61054c565b6040519081526020015b60405180910390f35b3480156100ce57600080fd5b5061007a6100dd366004610ccc"
        "565b61072d565b3480156100ee57600080fd5b50600254610102906001600160a01b031681565b6040516001600160a01b039091168152"
        "6020016100b9565b34801561012657600080fd5b50610102610135366004610d56565b610927565b6002546001600160a01b0316156101"
        "5057600080fd5b610158610940565b60408051306020820152600091829101604051602081830303815290604052905060006101858585"
        "610991565b90506000631415dae260e01b84836000866040516024016101a99493929190610dc5565b60408051601f1981840301815291"
        "8152602080830180516001600160e01b03166001600160e01b03199095169490941790935285518684012081517f2020dba91b30cc0006"
        "188af794c2fb30dd8520db7e2c088b7fc7c103c00ca494818601523081840152606081018990526080810187905260a080820192909252"
        "8251808203909201825260c0019091528051920191909120909150600280546001600160a01b0319166001600160a01b03929092169190"
        "91179055604080516001808252818301909252600091602082015b60608152602001906001900390816102775790505090508686808060"
        "1f016020809104026020016040519081016040528093929190818152602001838380828437600092018290525085518694509092501515"
        "90506102d8576102d8610df7565b60209081029190910101526001600160a01b037f000000000000000000000000a0f968eba6bbd08f28"
        "dc061c7856c157259833951663b4848df561031f6180006006610e23565b84622000008560006040518663ffffffff1660e01b81526004"
        "01610347959493929190610e70565b602060405180830381600087803b15801561036157600080fd5b505af1158015610375573d600080"
        "3e3d6000fd5b505050506040513d601f19601f820116820180604052508101906103999190610f01565b5050505050505050565b600080"
        "51602061107183398151915254600181146103c057600080fd5b6002600080516020611071833981519152556001600160a01b03871615"
        "6103e657600080fd5b6001600160a01b03881660009081526001602090815260408083208984529091529020548061041457600080fd5b"
        "6000604051806060016040528061800060016104309190610e23565b6001600160a01b031681526020018981526020016000801b815250"
        "905060007f000000000000000000000000a0f968eba6bbd08f28dc061c7856c157259833956001600160a01b031663ee97667b8989858a"
        "8a6040518663ffffffff1660e01b81526004016104a3959493929190610f50565b60206040518083038186803b1580156104bb57600080"
        "fd5b505afa1580156104cf573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906104f39190610f"
        "a4565b9050806104ff57600080fd5b6001600160a01b038b1660009081526001602090815260408083208c845290915281205561052d8b"
        "84610a41565b5050506001600080516020611071833981519152555050505050505050565b600080516020611071833981519152546000"
        "906001811461056c57600080fd5b6002600080516020611071833981519152556001600160a01b0385161561059257600080fd5b600061"
        "059e8534610fc6565b604080513360248201526001600160a01b038a1660448201526000606482018190526084820189905260a060a483"
        "015260c48083018290528351808403909101815260e49092019092526020810180516001600160e01b03166333f9ebdf60e21b17905291"
        "9250906002549091506001600160a01b037f000000000000000000000000a0f968eba6bbd08f28dc061c7856c1572598339581169163b4"
        "848df5918591168462200000600060405190808252806020026020018201604052801561067b57816020015b6060815260200190600190"
        "0390816106665790505b508b6040518763ffffffff1660e01b815260040161069d959493929190610e70565b6020604051808303818588"
        "803b1580156106b657600080fd5b505af11580156106ca573d6000803e3d6000fd5b50505050506040513d601f19601f82011682018060"
        "4052508101906106ef9190610f01565b336000908152600160208181526040808420858552909152909120979097556000805160206110"
        "718339815191529690965550939695505050505050565b600080516020611071833981519152546001811461074a57600080fd5b600260"
        "00805160206110718339815191525563ffffffff871660009081526020818152604080832089845290915290205460ff16156107885760"
        "0080fd5b6040805180820182526002546001600160a01b0316815281516020601f88018190048102820181019093528681526000928083"
        "01919089908990819084018382808284376000920182905250939094525050604080516020601f8b018190048102820181019092528981"
        "52939450909283925061081f918a908a9081908401838280828437600092019190915250610aa692505050565b9150915060007f000000"
        "000000000000000000a0f968eba6bbd08f28dc061c7856c157259833956001600160a01b03166352390d8d8c8c878b8b6040518663ffff"
        "ffff1660e01b8152600401610879959493929190610fdd565b60206040518083038186803b15801561089157600080fd5b505afa158015"
        "6108a5573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906108c99190610fa4565b9050806108"
        "d557600080fd5b63ffffffff8b166000908152602081815260408083208d84529091529020805460ff191660011790556109088383610a"
        "41565b5050505060016000805160206110718339815191525550505050505050565b60006001600160a01b03821661093b575060005b91"
        "9050565b60008051602061107183398151915280546001909155801561098e5760405162461bcd60e51b81526020600482015260026024"
        "8201526118a160f11b60448201526064015b60405180910390fd5b50565b60008061099f60208461103e565b90506201000081106109d8"
        "5760405162461bcd60e51b8152602060048201526002602482015261070760f41b6044820152606401610985565b600284846040516109"
        "ea929190611060565b602060405180830381855afa158015610a07573d6000803e3d6000fd5b5050506040513d601f19601f8201168201"
        "8060405250810190610a2a9190610f01565b6001600160f01b031660f09190911b179392505050565b6000826001600160a01b03168260"
        "405160006040518083038185875af1925050503d8060008114610a8e576040519150601f19603f3d011682016040523d82523d60006020"
        "84013e610a93565b606091505b5050905080610aa157600080fd5b505050565b6000808251603814610ab757600080fd5b600483810151"
        "90634417b5cb60e11b6001600160e01b031960e084901b1614610adf57600080fd5b601494019384015160349094015193949250505056"
        "5b60008083601f840112610b0757600080fd5b50813567ffffffffffffffff811115610b1f57600080fd5b602083019150836020828501"
        "011115610b3757600080fd5b9250929050565b60008060208385031215610b5157600080fd5b823567ffffffffffffffff811115610b68"
        "57600080fd5b610b7485828601610af5565b90969095509350505050565b80356001600160a01b038116811461093b57600080fd5b8035"
        "63ffffffff8116811461093b57600080fd5b60008083601f840112610bbd57600080fd5b50813567ffffffffffffffff811115610bd557"
        "600080fd5b6020830191508360208260051b8501011115610b3757600080fd5b600080600080600080600060c0888a031215610c0b5760"
        "0080fd5b610c1488610b80565b9650610c2260208901610b80565b955060408801359450610c3760608901610b97565b93506080880135"
        "925060a088013567ffffffffffffffff811115610c5a57600080fd5b610c668a828b01610bab565b989b979a5095985093969295929350"
        "5050565b60008060008060808587031215610c8f57600080fd5b610c9885610b80565b9350610ca660208601610b80565b925060408501"
        "359150606085013560038110610cc157600080fd5b939692955090935050565b60008060008060008060808789031215610ce557600080"
        "fd5b610cee87610b97565b955060208701359450604087013567ffffffffffffffff80821115610d1257600080fd5b610d1e8a838b0161"
        "0af5565b90965094506060890135915080821115610d3757600080fd5b50610d4489828a01610bab565b979a9699509497509295939492"
        "505050565b600060208284031215610d6857600080fd5b610d7182610b80565b9392505050565b6000815180845260005b81811015610d"
        "9e57602081850181015186830182015201610d82565b81811115610db0576000602083870101525b50601f01601f191692909201602001"
        "92915050565b84815283602082015260ff83166040820152608060608201526000610ded6080830184610d78565b969550505050505056"
        "5b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b600052601160045260246000fd5b60006001600160a01b03"
        "828116848216808303821115610e4557610e45610e0d565b01949350505050565b60038110610e6c57634e487b7160e01b600052602160"
        "045260246000fd5b9052565b6001600160a01b038616815260a06020808301829052600091610e9590840188610d78565b866040850152"
        "83810360608501528086518083528383019150838160051b84010184890160005b83811015610eea57601f19868403018552610ed88383"
        "51610d78565b94870194925090860190600101610ebc565b50508095505050505050610ded6080830184610e4e565b6000602082840312"
        "15610f1357600080fd5b5051919050565b81835260006001600160fb1b03831115610f3357600080fd5b8260051b808360208701376000"
        "9401602001938452509192915050565b63ffffffff8616815284602082015260018060a01b038451166040820152602084015160608201"
        "526040840151608082015260c060a08201526000610f9960c083018486610f1a565b979650505050505050565b60006020828403121561"
        "0fb657600080fd5b81518015158114610d7157600080fd5b600082821015610fd857610fd8610e0d565b500390565b63ffffffff861681"
        "528460208201526080604082015260018060a01b03845116608082015260006020850151604060a084015261101d60c0840182610d7856"
        "5b90508281036060840152611032818587610f1a565b98975050505050505050565b60008261105b57634e487b7160e01b600052601260"
        "045260246000fd5b500490565b818382376000910190815291905056fe8e94fed44239eb2314ab7a406345e6c5a8f0ccedf3b600de3d00"
        "4e672c33abf4a26469706673582212202c2ca0df5fe16e1f24f5b44a6cd8e0c312962248e41cc21559d927f2788dc3cd64736f6c634300"
        "08090033")};
    EXPECT_CALL(transaction, get_one(db::table::kCodeName, silkworm::ByteView{kCodeKey4}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kCodeValue4;
        }));

    // TransactionDatabase::get_one: TABLE Code > 1
    static Bytes kCodeKey5{*silkworm::from_hex("dcbf995c74c9488cf9772791f62699edd0d26d2a2d90e33920e8b604b44a34f0")};
    static Bytes kCodeValue5{*silkworm::from_hex(
        "600080356001600160e01b0319168152600080516020610e88833981519152602081905260409182902060e090925290546001600160a0"
        "1b0381166080818152600160a01b830461ffff1660a052600160b01b90920460ff16151560c052806100935760405162461bcd60e51b81"
        "526020600482015260016024820152602360f91b60448201526064015b60405180910390fd5b600383015460ff1615806100a957508160"
        "400151155b6100da5760405162461bcd60e51b8152602060048201526002602482015261713160f01b604482015260640161008a565b60"
        "405136600082376000803683855af43d806000843e8180156100fb578184f35b8184fd5b80516020820151604083015160005b83518110"
        "1561028957600084828151811061012b5761012b610c7b565b6020026020010151602001519050600085838151811061014d5761014d61"
        "0c7b565b6020026020010151600001519050600086848151811061016f5761016f610c7b565b6020026020010151604001519050600087"
        "858151811061019157610191610c7b565b602002602001015160600151905060008151116101d45760405162461bcd60e51b8152602060"
        "0482015260016024820152602160f91b604482015260640161008a565b60008460028111156101e8576101e8610c91565b14156101fe57"
        "6101f98382846102db565b610274565b600184600281111561021257610212610c91565b1415610223576101f9838284610408565b6002"
        "84600281111561023757610237610c91565b1415610248576101f9838284610539565b60405162461bcd60e51b81526020600482015260"
        "016024820152604360f81b604482015260640161008a565b505050508061028290610cbd565b905061010e565b50610294828261068c56"
        "5b7f87b829356b3403d36217eff1f66ee48eacd0a69015153aba4f0de29fe5340c308383836040516102c793929190610d34565b604051"
        "80910390a150505050565b3b151590565b600080516020610e888339815191526001600160a01b0384166103245760405162461bcd60e5"
        "1b81526020600482015260016024820152604760f81b604482015260640161008a565b61032d846107ad565b60005b8351811015610401"
        "57600084828151811061034d5761034d610c7b565b6020908102919091018101516001600160e01b031981166000908152858352604090"
        "819020815160608101835290546001600160a01b038116808352600160a01b820461ffff1695830195909552600160b01b900460ff1615"
        "159181019190915290925090156103e35760405162461bcd60e51b81526020600482015260016024820152602560f91b60448201526064"
        "0161008a565b6103ee878387610849565b5050806103fa90610cbd565b9050610330565b5050505050565b600080516020610e88833981"
        "5191526001600160a01b0384166104515760405162461bcd60e51b81526020600482015260016024820152604b60f81b60448201526064"
        "0161008a565b61045a846107ad565b60005b835181101561040157600084828151811061047a5761047a610c7b565b6020908102919091"
        "018101516001600160e01b031981166000908152858352604090819020815160608101835290546001600160a01b038116808352600160"
        "a01b820461ffff1695830195909552600160b01b900460ff161515918101919091529092509061050f5760405162461bcd60e51b815260"
        "20600482015260016024820152601360fa1b604482015260640161008a565b805161051b9083610938565b610526878387610849565b50"
        "508061053290610cbd565b905061045d565b600080516020610e888339815191526001600160a01b038416156105845760405162461bcd"
        "60e51b8152602060048201526002602482015261613160f01b604482015260640161008a565b81156105b75760405162461bcd60e51b81"
        "52602060048201526002602482015261713360f01b604482015260640161008a565b60005b835181101561040157600084828151811061"
        "05d7576105d7610c7b565b6020908102919091018101516001600160e01b03198116600090815285835260409081902081516060810183"
        "5290546001600160a01b038116808352600160a01b820461ffff1695830195909552600160b01b900460ff161515918101919091529092"
        "509061066d5760405162461bcd60e51b8152602060048201526002602482015261309960f11b604482015260640161008a565b80516106"
        "799083610938565b50508061068590610cbd565b90506105ba565b6001600160a01b0382166106d1578051156106cd5760405162461bcd"
        "60e51b81526020600482015260016024820152600960fb1b604482015260640161008a565b5050565b6001600160a01b03821630148061"
        "06e85750813b15155b6107195760405162461bcd60e51b8152602060048201526002602482015261339960f11b60448201526064016100"
        "8a565b6000826001600160a01b0316826040516107339190610e3e565b600060405180830381855af49150503d806000811461076e5760"
        "40519150601f19603f3d011682016040523d82523d6000602084013e610773565b606091505b50509050806107a85760405162461bcd60"
        "e51b81526020600482015260016024820152604960f81b604482015260640161008a565b505050565b6001600160a01b03811660009081"
        "52600080516020610ea88339815191526020526040902054600080516020610e888339815191529061ffff81166107a857506002810180"
        "546001600160a01b0393909316600081815260019384016020908152604082208501805461ffff191661ffff9097169690961790955582"
        "5493840183559182529290200180546001600160a01b0319169091179055565b6001600160a01b03928316600081815260008051602061"
        "0ea8833981519152602081815260408084208054825160608101845296875261ffff908116878501908152971515878401908152600160"
        "0160e01b03198a168752600080516020610e88833981519152855292862096518754985193519a166001600160b01b0319909816979097"
        "17600160a01b92909716919091029590951760ff60b01b1916600160b01b97151597909702969096179092559084528154600181018355"
        "918152929092206008830401805463ffffffff60079094166004026101000a938402191660e09290921c92909202179055565b60016001"
        "60e01b031981166000908152600080516020610e8883398151915260208181526040808420546001600160a01b03871685526000805160"
        "20610ea88339815191529092528320549192600160a01b90910461ffff169161099e90600190610e5a565b9050808214610a8a57600160"
        "0160a01b038516600090815260018401602052604081208054839081106109d3576109d3610c7b565b6000918252602080832060088304"
        "01546001600160a01b038a168452600188019091526040909220805460079092166004026101000a90920460e01b925082919085908110"
        "610a2457610a24610c7b565b600091825260208083206008830401805463ffffffff60079094166004026101000a938402191660e09590"
        "951c929092029390931790556001600160e01b031992909216825284905260409020805461ffff60a01b1916600160a01b61ffff851602"
        "1790555b6001600160a01b03851660009081526001840160205260409020805480610ab357610ab3610e71565b60008281526020808220"
        "600860001990940193840401805463ffffffff600460078716026101000a0219169055919092556001600160e01b031986168252849052"
        "6040902080546001600160b81b031916905580610401576001600160a01b0385166000908152600080516020610ea88339815191526020"
        "52604081206001908101547fc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131e5461040193899360008051"
        "6020610e888339815191529361ffff1692610b7d9190610e5a565b9050808214610c19576000836002018281548110610b9d57610b9d61"
        "0c7b565b6000918252602090912001546002850180546001600160a01b039092169250829185908110610bce57610bce610c7b565b6000"
        "91825260208083209190910180546001600160a01b0319166001600160a01b039485161790559290911681526001858101909252604090"
        "2001805461ffff191661ffff84161790555b82600201805480610c2c57610c2c610e71565b600082815260208082208301600019908101"
        "80546001600160a01b03191690559092019092556001600160a01b0395909516815260019384019094525050604090912001805461ffff"
        "19169055565b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b600052602160045260246000fd5b634e487b71"
        "60e01b600052601160045260246000fd5b6000600019821415610cd157610cd1610ca7565b5060010190565b60005b83811015610cf357"
        "8181015183820152602001610cdb565b83811115610d02576000848401525b50505050565b60008151808452610d208160208601602086"
        "01610cd8565b601f01601f19169290920160200192915050565b6000606080830181845280875180835260809250828601915082816005"
        "1b8701016020808b0160005b84811015610e0e57898403607f19018652815180516001600160a01b031685528381015188860190600381"
        "10610da357634e487b7160e01b600052602160045260246000fd5b86860152604082810151151590870152908901518986018990528051"
        "9182905284019060009060a08701905b80831015610df95783516001600160e01b0319168252928601926001929092019190860190610d"
        "cf565b50978501979550505090820190600101610d5d565b50506001600160a01b038a16908801528681036040880152610e308189610d"
        "08565b9a9950505050505050505050565b60008251610e50818460208701610cd8565b9190910192915050565b600082821015610e6c57"
        "610e6c610ca7565b500390565b634e487b7160e01b600052603160045260246000fdfec8fcad8db84d3cc18b4c41d551ea0ee66dd599cd"
        "e068d998e57d5e09332c131cc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131da2646970667358221220a8"
        "5fbbbd7fb2e8fdf8dc7d5520ad20e320ba47d7a4b549e786ef393caa48763364736f6c63430008090033")};
    EXPECT_CALL(transaction, get_one(db::table::kCodeName, silkworm::ByteView{kCodeKey5}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kCodeValue5;
        }));

    // TransactionDatabase::get_one: TABLE PlainState> 1
    static Bytes kPlainStateKey5{*silkworm::from_hex("6871c5aaa4e06861c86978cacf992471355b7330")};
    static Bytes kPlainStateValue5{*silkworm::from_hex("0d010101012003bd926f4f7e58b476046cb0e894971c99a49e79d41374a6339201c7b79655e4")};
    EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey5}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kPlainStateValue5;
        }));

    // TransactionDatabase::get_one: TABLE PlainState> 1
    static Bytes kPlainStateKey6{*silkworm::from_hex("0000000000000000000000000000000000000006")};
    static Bytes kPlainStateValue6{*silkworm::from_hex("020101")};
    EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey6}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kPlainStateValue6;
        }));

    // TransactionDatabase::get_one: TABLE PlainState> 1
    static Bytes kPlainStateKey7{*silkworm::from_hex("0000000000000000000000000000000000000008")};
    static Bytes kPlainStateValue7{*silkworm::from_hex("020101")};
    EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey7}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kPlainStateValue7;
        }));

    SECTION("from block number < to block number") {
        TraceFilter trace_filter = R"({
          "fromBlock": "0x6DDD03",
          "toBlock": "0x6DDD02"
        })"_json;

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};

        stream.open_object();
        spawn_and_wait(executor.trace_filter(trace_filter, &stream));
        stream.close_object();
        stream.close();

        nlohmann::json json = nlohmann::json::parse(string_writer.get_content());
        CHECK(json == R"({
            "error":{
                "code":-32000,
                "message":"invalid parameters: fromBlock cannot be greater than toBlock"
            }
        })"_json);
    }

    SECTION("from block to block") {
        TraceFilter trace_filter = R"({
          "fromBlock": "0x6DDD02",
          "toBlock": "0x6DDD03"
        })"_json;

        // TransactionDatabase::get_one: TABLE CanonicalHeader
        static Bytes kCanonicalHeaderKey3{*silkworm::from_hex("00000000006ddd04")};
        static Bytes kCanonicalHeaderValue3{*silkworm::from_hex("1b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kCanonicalHeaderKey3}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kCanonicalHeaderValue3;
            }));

        // TransactionDatabase::get: TABLE Header
        static Bytes kHeaderKey2{*silkworm::from_hex("00000000006ddd041b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        static Bytes kHeaderValue2{*silkworm::from_hex(
            "f9025ba0a316f156582fb5fba2166910becdb6342965a801fa473e18cd6a0c06143cac1aa01dcc4de8dec75d7aab85b567b6ccd41ad312"
            "451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a000636fe848d9d0dd8d3fe77deef0286329b01f"
            "4e971501d1dc481365deea77bfa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6"
            "ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000001836ddd048401c9c380808462ca3c74b8614e65746865726d696e6420312e31332e332d302d306533323839663535"
            "2d3230a499270541450663356185c61f970959545219dee7616763658a87d3c80730c32cca058d57ccc16cc0b0ca4269c4dee474ee3612"
            "f83cbf54f9fbffddba6d154401a00000000000000000000000000000000000000000000000000000000000000000880000000000000000"
            "07")};
        EXPECT_CALL(transaction, get_one(db::table::kHeadersName, silkworm::ByteView{kHeaderKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kHeaderValue2;
            }));

        // TransactionDatabase::get: TABLE BlockBody
        static Bytes kBlockBodyKey2{*silkworm::from_hex("00000000006ddd041b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        static Bytes kBlockBodyValue2{*silkworm::from_hex("c78405c62e6f02c0")};
        EXPECT_CALL(transaction, get_one(db::table::kBlockBodiesName, silkworm::ByteView{kBlockBodyKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kBlockBodyValue2;
            }));

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};

        stream.open_object();
        spawn_and_wait(executor.trace_filter(trace_filter, &stream));
        stream.close_object();
        stream.close();

        nlohmann::json json = nlohmann::json::parse(string_writer.get_content());
        CHECK(json["result"] == R"([
            {
                "action": {
                    "author": "0x0000000000000000000000000000000000000000",
                    "rewardType": "block",
                    "value": "0x1bc16d674ec80000"
                },
                "blockHash": "0xa87009e08f9af73efe86d702561afcf98f277a8acec60b97869969e367c12d66",
                "blockNumber": 7200002,
                "result": null,
                "subtraces": 0,
                "traceAddress": [],
                "type": "reward"
            },
            {
                "action": {
                    "author": "0x0000000000000000000000000000000000000000",
                    "rewardType": "block",
                    "value": "0x1bc16d674ec80000"
                },
                "blockHash": "0xa316f156582fb5fba2166910becdb6342965a801fa473e18cd6a0c06143cac1a",
                "blockNumber": 7200003,
                "result": null,
                "subtraces": 0,
                "traceAddress": [],
                "type": "reward"
            }
        ])"_json);
    }

    SECTION("from block to block with fromAddress") {
        TraceFilter trace_filter = R"({
          "fromBlock": "0x6DDD02",
          "toBlock": "0x6DDD03",
          "fromAddress": ["0x2031832e54a2200bf678286f560f49a950db2ad5"]
        })"_json;

        // TransactionDatabase::get_one: TABLE CanonicalHeader
        static Bytes kCanonicalHeaderKey3{*silkworm::from_hex("00000000006ddd04")};
        static Bytes kCanonicalHeaderValue3{*silkworm::from_hex("1b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kCanonicalHeaderKey3}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kCanonicalHeaderValue3;
            }));

        // TransactionDatabase::get: TABLE Header
        static Bytes kHeaderKey2{*silkworm::from_hex("00000000006ddd041b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        static Bytes kHeaderValue2{*silkworm::from_hex(
            "f9025ba0a316f156582fb5fba2166910becdb6342965a801fa473e18cd6a0c06143cac1aa01dcc4de8dec75d7aab85b567b6ccd41ad312"
            "451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a000636fe848d9d0dd8d3fe77deef0286329b01f"
            "4e971501d1dc481365deea77bfa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6"
            "ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000001836ddd048401c9c380808462ca3c74b8614e65746865726d696e6420312e31332e332d302d306533323839663535"
            "2d3230a499270541450663356185c61f970959545219dee7616763658a87d3c80730c32cca058d57ccc16cc0b0ca4269c4dee474ee3612"
            "f83cbf54f9fbffddba6d154401a00000000000000000000000000000000000000000000000000000000000000000880000000000000000"
            "07")};
        EXPECT_CALL(transaction, get_one(db::table::kHeadersName, silkworm::ByteView{kHeaderKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kHeaderValue2;
            }));

        // TransactionDatabase::get: TABLE BlockBody
        static Bytes kBlockBodyKey2{*silkworm::from_hex("00000000006ddd041b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        static Bytes kBlockBodyValue2{*silkworm::from_hex("c78405c62e6f02c0")};
        EXPECT_CALL(transaction, get_one(db::table::kBlockBodiesName, silkworm::ByteView{kBlockBodyKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kBlockBodyValue2;
            }));

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};

        stream.open_object();
        spawn_and_wait(executor.trace_filter(trace_filter, &stream));
        stream.close_object();
        stream.close();

        nlohmann::json json = nlohmann::json::parse(string_writer.get_content());
        CHECK(json["result"] == R"([
        ])"_json);
    }

    SECTION("from block to block with toAddress") {
        TraceFilter trace_filter = R"({
          "fromBlock": "0x6DDD02",
          "toBlock": "0x6DDD03",
          "fromAddress": ["0x2031832e54a2200bf678286f560f49a950db2ad5"]
        })"_json;

        // TransactionDatabase::get_one: TABLE CanonicalHeader
        static Bytes kCanonicalHeaderKey3{*silkworm::from_hex("00000000006ddd04")};
        static Bytes kCanonicalHeaderValue3{*silkworm::from_hex("1b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kCanonicalHeaderKey3}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kCanonicalHeaderValue3;
            }));

        // TransactionDatabase::get: TABLE Header
        static Bytes kHeaderKey2{*silkworm::from_hex("00000000006ddd041b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        static Bytes kHeaderValue2{*silkworm::from_hex(
            "f9025ba0a316f156582fb5fba2166910becdb6342965a801fa473e18cd6a0c06143cac1aa01dcc4de8dec75d7aab85b567b6ccd41ad312"
            "451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a000636fe848d9d0dd8d3fe77deef0286329b01f"
            "4e971501d1dc481365deea77bfa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6"
            "ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000001836ddd048401c9c380808462ca3c74b8614e65746865726d696e6420312e31332e332d302d306533323839663535"
            "2d3230a499270541450663356185c61f970959545219dee7616763658a87d3c80730c32cca058d57ccc16cc0b0ca4269c4dee474ee3612"
            "f83cbf54f9fbffddba6d154401a00000000000000000000000000000000000000000000000000000000000000000880000000000000000"
            "07")};
        EXPECT_CALL(transaction, get_one(db::table::kHeadersName, silkworm::ByteView{kHeaderKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kHeaderValue2;
            }));

        // TransactionDatabase::get: TABLE BlockBody
        static Bytes kBlockBodyKey2{*silkworm::from_hex("00000000006ddd041b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        static Bytes kBlockBodyValue2{*silkworm::from_hex("c78405c62e6f02c0")};
        EXPECT_CALL(transaction, get_one(db::table::kBlockBodiesName, silkworm::ByteView{kBlockBodyKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kBlockBodyValue2;
            }));

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};

        stream.open_object();
        spawn_and_wait(executor.trace_filter(trace_filter, &stream));
        stream.close_object();
        stream.close();

        nlohmann::json json = nlohmann::json::parse(string_writer.get_content());
        CHECK(json["result"] == R"([
        ])"_json);
    }

    SECTION("from block to block with count=0") {
        TraceFilter trace_filter = R"({
          "fromBlock": "0x6DDD02",
          "toBlock": "0x6DDD03",
          "count": 0
        })"_json;

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};

        stream.open_object();
        spawn_and_wait(executor.trace_filter(trace_filter, &stream));
        stream.close_object();
        stream.close();

        nlohmann::json json = nlohmann::json::parse(string_writer.get_content());
        CHECK(json["result"] == R"([
        ])"_json);
    }

    SECTION("from block to block with count=1") {
        TraceFilter trace_filter = R"({
          "fromBlock": "0x6DDD02",
          "toBlock": "0x6DDD03",
          "count": 1
        })"_json;

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};

        stream.open_object();
        spawn_and_wait(executor.trace_filter(trace_filter, &stream));
        stream.close_object();
        stream.close();

        nlohmann::json json = nlohmann::json::parse(string_writer.get_content());
        CHECK(json["result"] == R"([
            {
                "action": {
                    "author": "0x0000000000000000000000000000000000000000",
                    "rewardType": "block",
                    "value": "0x1bc16d674ec80000"
                },
                "blockHash": "0xa87009e08f9af73efe86d702561afcf98f277a8acec60b97869969e367c12d66",
                "blockNumber": 7200002,
                "result": null,
                "subtraces": 0,
                "traceAddress": [],
                "type": "reward"
            }
        ])"_json);
    }

    SECTION("from block to block with after=0") {
        TraceFilter trace_filter = R"({
          "fromBlock": "0x6DDD02",
          "toBlock": "0x6DDD03",
          "after": 0
        })"_json;

        // TransactionDatabase::get_one: TABLE CanonicalHeader
        static Bytes kCanonicalHeaderKey3{*silkworm::from_hex("00000000006ddd04")};
        static Bytes kCanonicalHeaderValue3{*silkworm::from_hex("1b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kCanonicalHeaderKey3}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kCanonicalHeaderValue3;
            }));

        // TransactionDatabase::get: TABLE Header
        static Bytes kHeaderKey2{*silkworm::from_hex("00000000006ddd041b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        static Bytes kHeaderValue2{*silkworm::from_hex(
            "f9025ba0a316f156582fb5fba2166910becdb6342965a801fa473e18cd6a0c06143cac1aa01dcc4de8dec75d7aab85b567b6ccd41ad312"
            "451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a000636fe848d9d0dd8d3fe77deef0286329b01f"
            "4e971501d1dc481365deea77bfa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6"
            "ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000001836ddd048401c9c380808462ca3c74b8614e65746865726d696e6420312e31332e332d302d306533323839663535"
            "2d3230a499270541450663356185c61f970959545219dee7616763658a87d3c80730c32cca058d57ccc16cc0b0ca4269c4dee474ee3612"
            "f83cbf54f9fbffddba6d154401a00000000000000000000000000000000000000000000000000000000000000000880000000000000000"
            "07")};
        EXPECT_CALL(transaction, get_one(db::table::kHeadersName, silkworm::ByteView{kHeaderKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kHeaderValue2;
            }));

        // TransactionDatabase::get: TABLE BlockBody
        static Bytes kBlockBodyKey2{*silkworm::from_hex("00000000006ddd041b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        static Bytes kBlockBodyValue2{*silkworm::from_hex("c78405c62e6f02c0")};
        EXPECT_CALL(transaction, get_one(db::table::kBlockBodiesName, silkworm::ByteView{kBlockBodyKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kBlockBodyValue2;
            }));

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};

        stream.open_object();
        spawn_and_wait(executor.trace_filter(trace_filter, &stream));
        stream.close_object();
        stream.close();

        nlohmann::json json = nlohmann::json::parse(string_writer.get_content());
        CHECK(json["result"] == R"([
            {
                "action": {
                    "author": "0x0000000000000000000000000000000000000000",
                    "rewardType": "block",
                    "value": "0x1bc16d674ec80000"
                },
                "blockHash": "0xa87009e08f9af73efe86d702561afcf98f277a8acec60b97869969e367c12d66",
                "blockNumber": 7200002,
                "result": null,
                "subtraces": 0,
                "traceAddress": [],
                "type": "reward"
            },
            {
                "action": {
                    "author": "0x0000000000000000000000000000000000000000",
                    "rewardType": "block",
                    "value": "0x1bc16d674ec80000"
                },
                "blockHash": "0xa316f156582fb5fba2166910becdb6342965a801fa473e18cd6a0c06143cac1a",
                "blockNumber": 7200003,
                "result": null,
                "subtraces": 0,
                "traceAddress": [],
                "type": "reward"
            }
        ])"_json);
    }

    SECTION("from block to block with after=1") {
        TraceFilter trace_filter = R"({
          "fromBlock": "0x6DDD02",
          "toBlock": "0x6DDD03",
          "after": 1
        })"_json;

        // TransactionDatabase::get_one: TABLE CanonicalHeader
        static Bytes kCanonicalHeaderKey3{*silkworm::from_hex("00000000006ddd04")};
        static Bytes kCanonicalHeaderValue3{*silkworm::from_hex("1b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kCanonicalHeaderKey3}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kCanonicalHeaderValue3;
            }));

        // TransactionDatabase::get: TABLE Header
        static Bytes kHeaderKey2{*silkworm::from_hex("00000000006ddd041b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        static Bytes kHeaderValue2{*silkworm::from_hex(
            "f9025ba0a316f156582fb5fba2166910becdb6342965a801fa473e18cd6a0c06143cac1aa01dcc4de8dec75d7aab85b567b6ccd41ad312"
            "451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a000636fe848d9d0dd8d3fe77deef0286329b01f"
            "4e971501d1dc481365deea77bfa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6"
            "ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000001836ddd048401c9c380808462ca3c74b8614e65746865726d696e6420312e31332e332d302d306533323839663535"
            "2d3230a499270541450663356185c61f970959545219dee7616763658a87d3c80730c32cca058d57ccc16cc0b0ca4269c4dee474ee3612"
            "f83cbf54f9fbffddba6d154401a00000000000000000000000000000000000000000000000000000000000000000880000000000000000"
            "07")};
        EXPECT_CALL(transaction, get_one(db::table::kHeadersName, silkworm::ByteView{kHeaderKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kHeaderValue2;
            }));

        // TransactionDatabase::get: TABLE BlockBody
        static Bytes kBlockBodyKey2{*silkworm::from_hex("00000000006ddd041b9ac5d63ba5c6a7e0c40a339499eef9b8b45fa247e701516f35a2357ccdaf1e")};
        static Bytes kBlockBodyValue2{*silkworm::from_hex("c78405c62e6f02c0")};
        EXPECT_CALL(transaction, get_one(db::table::kBlockBodiesName, silkworm::ByteView{kBlockBodyKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kBlockBodyValue2;
            }));

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};

        stream.open_object();
        spawn_and_wait(executor.trace_filter(trace_filter, &stream));
        stream.close_object();
        stream.close();

        nlohmann::json json = nlohmann::json::parse(string_writer.get_content());
        CHECK(json["result"] == R"([
            {
                "action": {
                    "author": "0x0000000000000000000000000000000000000000",
                    "rewardType": "block",
                    "value": "0x1bc16d674ec80000"
                },
                "blockHash": "0xa316f156582fb5fba2166910becdb6342965a801fa473e18cd6a0c06143cac1a",
                "blockNumber": 7200003,
                "result": null,
                "subtraces": 0,
                "traceAddress": [],
                "type": "reward"
            }
        ])"_json);
    }
}
#endif

TEST_CASE("VmTrace json serialization") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    TraceEx trace_ex;
    trace_ex.used = 5000;
    trace_ex.stack.emplace_back("0xdeadbeaf");
    trace_ex.memory = TraceMemory{10, 0, "data"};
    trace_ex.storage = TraceStorage{"key", "value"};

    TraceOp trace_op;
    trace_op.gas_cost = 42;
    trace_op.trace_ex = trace_ex;
    trace_op.idx = "12";
    trace_op.op_name = "PUSH1";
    trace_op.pc = 27;
    VmTrace vm_trace;

    vm_trace.code = "0xdeadbeaf";
    vm_trace.ops.push_back(trace_op);

    SECTION("VmTrace") {
        CHECK(nlohmann::json(vm_trace) == R"({
            "code": "0xdeadbeaf",
            "ops": [
                {
                    "cost":42,
                    "ex":{
                        "mem": null,
                        "push":["0xdeadbeaf"],
                        "store":{
                            "key":"key",
                            "val":"value"
                        },
                        "used":5000
                    },
                    "idx":"12",
                    "op":"PUSH1",
                    "pc":27,
                    "sub":null
                }
            ]
        })"_json);
    }
    SECTION("TraceOp") {
        CHECK(nlohmann::json(trace_op) == R"({
            "cost":42,
            "ex":{
                "mem": null,
                "push":["0xdeadbeaf"],
                "store":{
                    "key":"key",
                    "val":"value"
                },
                "used":5000
            },
            "idx":"12",
            "op":"PUSH1",
            "pc":27,
            "sub":null
        })"_json);
    }
    SECTION("TraceEx") {
        CHECK(nlohmann::json(trace_ex) == R"({
            "mem": null,
            "push":["0xdeadbeaf"],
            "store":{
                "key":"key",
                "val":"value"
            },
            "used":5000
        })"_json);
    }
    SECTION("TraceMemory") {
        const auto& memory = trace_ex.memory.value();
        CHECK(nlohmann::json(memory) == R"({
            "data":"data",
            "off":10
        })"_json);
    }
    SECTION("TraceStorage") {
        const auto& storage = trace_ex.storage.value();
        CHECK(nlohmann::json(storage) == R"({
            "key":"key",
            "val":"value"
        })"_json);
    }
}

TEST_CASE("TraceAction json serialization") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    TraceAction trace_action;
    trace_action.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
    trace_action.gas = 1000;
    trace_action.value = intx::uint256{0xdeadbeaf};

    SECTION("basic") {
        CHECK(nlohmann::json(trace_action) == R"({
            "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
            "gas": "0x3e8",
            "value": "0xdeadbeaf"
        })"_json);
    }
    SECTION("with to") {
        trace_action.to = 0xe0a2bd4258d2768837baa26a28fe71dc079f8aaa_address;
        CHECK(nlohmann::json(trace_action) == R"({
            "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
            "to": "0xe0a2bd4258d2768837baa26a28fe71dc079f8aaa",
            "gas": "0x3e8",
            "value": "0xdeadbeaf"
        })"_json);
    }
    SECTION("with input") {
        trace_action.input = *silkworm::from_hex("0xdeadbeaf");
        CHECK(nlohmann::json(trace_action) == R"({
            "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
            "gas": "0x3e8",
            "input": "0xdeadbeaf",
            "value": "0xdeadbeaf"
        })"_json);
    }
    SECTION("with init") {
        trace_action.init = *silkworm::from_hex("0xdeadbeaf");
        CHECK(nlohmann::json(trace_action) == R"({
            "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
            "gas": "0x3e8",
            "init": "0xdeadbeaf",
            "value": "0xdeadbeaf"
        })"_json);
    }
}

TEST_CASE("TraceResult json serialization") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    TraceResult trace_result;
    trace_result.address = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
    trace_result.code = *silkworm::from_hex("0x1234567890abcdef");
    trace_result.gas_used = 1000;

    CHECK(nlohmann::json(trace_result) == R"({
        "address": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
        "code": "0x1234567890abcdef",
        "gasUsed": "0x3e8"
    })"_json);
}

TEST_CASE("Trace json serialization") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    TraceAction trace_action;
    trace_action.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
    trace_action.gas = 1000;
    trace_action.value = intx::uint256{0xdeadbeaf};

    Trace trace;
    trace.action = trace_action;
    trace.type = "CALL";

    SECTION("basic with trace action") {
        CHECK(nlohmann::json(trace) == R"({
            "action": {
                "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                "gas": "0x3e8",
                "value": "0xdeadbeaf"
            },
            "result": null,
            "subtraces": 0,
            "traceAddress": [],
            "type": "CALL"
        })"_json);
    }

    SECTION("basic with reward action") {
        RewardAction reward_action;
        reward_action.author = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84d8_address;
        reward_action.reward_type = "block";
        reward_action.value = intx::uint256{0xdeadbeaf};

        trace.action = reward_action;
        trace.type = "reward";

        CHECK(nlohmann::json(trace) == R"({
            "action": {
                "author": "0xe0a2bd4258d2768837baa26a28fe71dc079f84d8",
                "rewardType": "block",
                "value": "0xdeadbeaf"
            },
            "result": null,
            "subtraces": 0,
            "traceAddress": [],
            "type": "reward"
        })"_json);
    }

    SECTION("with trace_result") {
        TraceResult trace_result;
        trace_result.address = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c8_address;
        trace_result.code = *silkworm::from_hex("0x1234567890abcdef");
        trace_result.gas_used = 1000;

        trace.trace_result = trace_result;

        CHECK(nlohmann::json(trace) == R"({
            "action": {
                "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                "gas": "0x3e8",
                "value": "0xdeadbeaf"
            },
            "result": {
                "address": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c8",
                "code": "0x1234567890abcdef",
                "gasUsed": "0x3e8"
            },
            "subtraces": 0,
            "traceAddress": [],
            "type": "CALL"
        })"_json);
    }
    SECTION("with error") {
        trace.error = "error";

        CHECK(nlohmann::json(trace) == R"({
            "action": {
                "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                "gas": "0x3e8",
                "value": "0xdeadbeaf"
            },
            "error": "error",
            "result": null,
            "subtraces": 0,
            "traceAddress": [],
            "type": "CALL"
        })"_json);
    }
}

TEST_CASE("StateDiff json serialization") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    StateDiff state_diff;

    SECTION("basic") {
        CHECK(nlohmann::json(state_diff) == R"({
        })"_json);
    }
    SECTION("with 1 entry") {
        StateDiffEntry entry;

        state_diff.insert(std::pair<std::string, StateDiffEntry>("item", entry));

        CHECK(nlohmann::json(state_diff) == R"({
            "item": {
                "balance": "=",
                "code": "=",
                "nonce": "=",
                "storage": {}
            }
        })"_json);
    }
}

TEST_CASE("DiffValue json serialization") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    SECTION("no entries") {
        DiffValue dv;

        CHECK(nlohmann::json(dv) == R"("=")"_json);
    }
    SECTION("only from entry") {
        DiffValue dv{"0xe0a2bd4258d2768837baa26a28fe71dc079f84c7"};

        CHECK(nlohmann::json(dv) == R"({
            "-":"0xe0a2bd4258d2768837baa26a28fe71dc079f84c7"
        })"_json);
    }
    SECTION("only to entry") {
        DiffValue dv{{}, "0xe0a2bd4258d2768837baa26a28fe71dc079f84c8"};

        CHECK(nlohmann::json(dv) == R"({
            "+": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c8"
        })"_json);
    }
    SECTION("both entries") {
        DiffValue dv{"0xe0a2bd4258d2768837baa26a28fe71dc079f84c7", "0xe0a2bd4258d2768837baa26a28fe71dc079f84c8"};

        CHECK(nlohmann::json(dv) == R"({
            "*": {
                "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                "to": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c8"
            }
        })"_json);
    }
}

TEST_CASE("copy_stack") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    const std::size_t stack_size{32};
    evmone::uint256 stack[stack_size] = {
        {0x00}, {0x01}, {0x02}, {0x03}, {0x04}, {0x05}, {0x06}, {0x07}, {0x08}, {0x09}, {0x0A}, {0x0B}, {0x0C}, {0x0D}, {0x0E}, {0x0F}, {0x10}, {0x11}, {0x12}, {0x13}, {0x14}, {0x15}, {0x16}, {0x17}, {0x18}, {0x19}, {0x1A}, {0x1B}, {0x1C}, {0x1D}, {0x1E}, {0x1F}};
    evmone::uint256* top_stack = &stack[stack_size - 1];

    SECTION("PUSHX") {
        for (std::uint8_t op_code = evmc_opcode::OP_PUSH1; op_code < evmc_opcode::OP_PUSH32 + 1; ++op_code) {
            std::vector<std::string> trace_stack;
            copy_stack(op_code, top_stack, trace_stack);

            CHECK(trace_stack.size() == 1);
            CHECK(trace_stack[0] == "0x1f");
        }
    }

    SECTION("OP_SWAPX") {
        for (std::uint8_t op_code = evmc_opcode::OP_SWAP1; op_code < evmc_opcode::OP_SWAP16 + 1; ++op_code) {
            std::vector<std::string> trace_stack;
            copy_stack(op_code, top_stack, trace_stack);

            std::uint8_t size = op_code - evmc_opcode::OP_SWAP1 + 2;
            CHECK(trace_stack.size() == size);
            for (std::size_t idx = 0; idx < size; ++idx) {
                CHECK(trace_stack[idx] == "0x" + intx::to_string(stack[stack_size - size + idx], 16));
            }
        }
    }

    SECTION("OP_DUPX") {
        for (std::uint8_t op_code = evmc_opcode::OP_DUP1; op_code < evmc_opcode::OP_DUP16 + 1; ++op_code) {
            std::vector<std::string> trace_stack;
            copy_stack(op_code, top_stack, trace_stack);

            std::uint8_t size = op_code - evmc_opcode::OP_DUP1 + 2;
            CHECK(trace_stack.size() == size);
            for (std::size_t idx = 0; idx < size; ++idx) {
                CHECK(trace_stack[idx] == "0x" + intx::to_string(stack[stack_size - size + idx], 16));
            }
        }
    }

    SECTION("OP_OTHER") {
        for (std::uint8_t op_code = evmc_opcode::OP_STOP; op_code < evmc_opcode::OP_SELFDESTRUCT; ++op_code) {
            std::vector<std::string> trace_stack;
            switch (op_code) {
                case evmc_opcode::OP_PUSH1:
                case evmc_opcode::OP_PUSH2:
                case evmc_opcode::OP_PUSH3:
                case evmc_opcode::OP_PUSH4:
                case evmc_opcode::OP_PUSH5:
                case evmc_opcode::OP_PUSH6:
                case evmc_opcode::OP_PUSH7:
                case evmc_opcode::OP_PUSH8:
                case evmc_opcode::OP_PUSH9:
                case evmc_opcode::OP_PUSH10:
                case evmc_opcode::OP_PUSH11:
                case evmc_opcode::OP_PUSH12:
                case evmc_opcode::OP_PUSH13:
                case evmc_opcode::OP_PUSH14:
                case evmc_opcode::OP_PUSH15:
                case evmc_opcode::OP_PUSH16:
                case evmc_opcode::OP_PUSH17:
                case evmc_opcode::OP_PUSH18:
                case evmc_opcode::OP_PUSH19:
                case evmc_opcode::OP_PUSH20:
                case evmc_opcode::OP_PUSH21:
                case evmc_opcode::OP_PUSH22:
                case evmc_opcode::OP_PUSH23:
                case evmc_opcode::OP_PUSH24:
                case evmc_opcode::OP_PUSH25:
                case evmc_opcode::OP_PUSH26:
                case evmc_opcode::OP_PUSH27:
                case evmc_opcode::OP_PUSH28:
                case evmc_opcode::OP_PUSH29:
                case evmc_opcode::OP_PUSH30:
                case evmc_opcode::OP_PUSH31:
                case evmc_opcode::OP_PUSH32:
                case evmc_opcode::OP_SWAP1:
                case evmc_opcode::OP_SWAP2:
                case evmc_opcode::OP_SWAP3:
                case evmc_opcode::OP_SWAP4:
                case evmc_opcode::OP_SWAP5:
                case evmc_opcode::OP_SWAP6:
                case evmc_opcode::OP_SWAP7:
                case evmc_opcode::OP_SWAP8:
                case evmc_opcode::OP_SWAP9:
                case evmc_opcode::OP_SWAP10:
                case evmc_opcode::OP_SWAP11:
                case evmc_opcode::OP_SWAP12:
                case evmc_opcode::OP_SWAP13:
                case evmc_opcode::OP_SWAP14:
                case evmc_opcode::OP_SWAP15:
                case evmc_opcode::OP_SWAP16:
                case evmc_opcode::OP_DUP1:
                case evmc_opcode::OP_DUP2:
                case evmc_opcode::OP_DUP3:
                case evmc_opcode::OP_DUP4:
                case evmc_opcode::OP_DUP5:
                case evmc_opcode::OP_DUP6:
                case evmc_opcode::OP_DUP7:
                case evmc_opcode::OP_DUP8:
                case evmc_opcode::OP_DUP9:
                case evmc_opcode::OP_DUP10:
                case evmc_opcode::OP_DUP11:
                case evmc_opcode::OP_DUP12:
                case evmc_opcode::OP_DUP13:
                case evmc_opcode::OP_DUP14:
                case evmc_opcode::OP_DUP15:
                case evmc_opcode::OP_DUP16:
                    break;
                case evmc_opcode::OP_CALLDATALOAD:
                case evmc_opcode::OP_SLOAD:
                case evmc_opcode::OP_MLOAD:
                case evmc_opcode::OP_CALLDATASIZE:
                case evmc_opcode::OP_LT:
                case evmc_opcode::OP_GT:
                case evmc_opcode::OP_DIV:
                case evmc_opcode::OP_SDIV:
                case evmc_opcode::OP_SAR:
                case evmc_opcode::OP_AND:
                case evmc_opcode::OP_EQ:
                case evmc_opcode::OP_CALLVALUE:
                case evmc_opcode::OP_ISZERO:
                case evmc_opcode::OP_ADD:
                case evmc_opcode::OP_EXP:
                case evmc_opcode::OP_CALLER:
                case evmc_opcode::OP_KECCAK256:
                case evmc_opcode::OP_SUB:
                case evmc_opcode::OP_ADDRESS:
                case evmc_opcode::OP_GAS:
                case evmc_opcode::OP_MUL:
                case evmc_opcode::OP_RETURNDATASIZE:
                case evmc_opcode::OP_NOT:
                case evmc_opcode::OP_SHR:
                case evmc_opcode::OP_SHL:
                case evmc_opcode::OP_EXTCODESIZE:
                case evmc_opcode::OP_SLT:
                case evmc_opcode::OP_OR:
                case evmc_opcode::OP_NUMBER:
                case evmc_opcode::OP_PC:
                case evmc_opcode::OP_TIMESTAMP:
                case evmc_opcode::OP_BALANCE:
                case evmc_opcode::OP_SELFBALANCE:
                case evmc_opcode::OP_MULMOD:
                case evmc_opcode::OP_ADDMOD:
                case evmc_opcode::OP_BASEFEE:
                case evmc_opcode::OP_BLOCKHASH:
                case evmc_opcode::OP_BYTE:
                case evmc_opcode::OP_XOR:
                case evmc_opcode::OP_ORIGIN:
                case evmc_opcode::OP_CODESIZE:
                case evmc_opcode::OP_MOD:
                case evmc_opcode::OP_SIGNEXTEND:
                case evmc_opcode::OP_GASLIMIT:
                case evmc_opcode::OP_PREVRANDAO:
                case evmc_opcode::OP_SGT:
                case evmc_opcode::OP_GASPRICE:
                case evmc_opcode::OP_MSIZE:
                case evmc_opcode::OP_EXTCODEHASH:
                case evmc_opcode::OP_STATICCALL:
                case evmc_opcode::OP_DELEGATECALL:
                case evmc_opcode::OP_CALL:
                case evmc_opcode::OP_CALLCODE:
                case evmc_opcode::OP_CREATE:
                case evmc_opcode::OP_CREATE2:
                case evmc_opcode::OP_COINBASE:
                case evmc_opcode::OP_CHAINID:
                case evmc_opcode::OP_SMOD:
                    copy_stack(op_code, top_stack, trace_stack);

                    CHECK(trace_stack.size() == 1);
                    CHECK(trace_stack[0] == "0x1f");
                    break;
                default:
                    copy_stack(op_code, top_stack, trace_stack);

                    CHECK(trace_stack.empty());
                    break;
            }
        }
    }
}

TEST_CASE("copy_memory") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    evmone::Memory memory;
    for (std::uint8_t idx = 0; idx < 16; ++idx) {
        memory[idx] = idx;
    }

    SECTION("TRACE_MEMORY NOT SET") {
        std::optional<TraceMemory> trace_memory;
        copy_memory(memory, trace_memory);

        CHECK(trace_memory.has_value() == false);
    }
    SECTION("TRACE_MEMORY LEN == 0") {
        std::optional<TraceMemory> trace_memory = TraceMemory{0, 0};
        copy_memory(memory, trace_memory);

        CHECK(trace_memory.has_value() == false);
    }
    SECTION("TRACE_MEMORY LEN != 0") {
        std::optional<TraceMemory> trace_memory = TraceMemory{0, 10};
        copy_memory(memory, trace_memory);

        CHECK(trace_memory.has_value() == true);
        CHECK(nlohmann::json(trace_memory.value()) == R"({
            "off":0,
            "data":"0x00010203040506070809"
        })"_json);
    }
}

TEST_CASE("copy_store") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    const std::size_t stack_size{32};
    evmone::uint256 stack[stack_size] = {
        {0x00}, {0x01}, {0x02}, {0x03}, {0x04}, {0x05}, {0x06}, {0x07}, {0x08}, {0x09}, {0x0A}, {0x0B}, {0x0C}, {0x0D}, {0x0E}, {0x0F}, {0x10}, {0x11}, {0x12}, {0x13}, {0x14}, {0x15}, {0x16}, {0x17}, {0x18}, {0x19}, {0x1A}, {0x1B}, {0x1C}, {0x1D}, {0x1E}, {0x1F}};
    evmone::uint256* top_stack = &stack[stack_size - 1];

    SECTION("op_code == OP_SSTORE") {
        std::optional<TraceStorage> trace_storage;
        copy_store(evmc_opcode::OP_SSTORE, top_stack, trace_storage);

        CHECK(trace_storage.has_value() == true);
        CHECK(nlohmann::json(trace_storage.value()) == R"({
            "key":"0x1f",
            "val":"0x1e"
        })"_json);
    }
    SECTION("op_code != OP_SSTORE") {
        std::optional<TraceStorage> trace_storage;
        copy_store(evmc_opcode::OP_CALLDATASIZE, top_stack, trace_storage);

        CHECK(trace_storage.has_value() == false);
    }
}

TEST_CASE("copy_memory_offset_len") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    const std::size_t stack_size{32};
    evmone::uint256 stack[stack_size] = {
        {0x00}, {0x01}, {0x02}, {0x03}, {0x04}, {0x05}, {0x06}, {0x07}, {0x08}, {0x09}, {0x0A}, {0x0B}, {0x0C}, {0x0D}, {0x0E}, {0x0F}, {0x10}, {0x11}, {0x12}, {0x13}, {0x14}, {0x15}, {0x16}, {0x17}, {0x18}, {0x19}, {0x1A}, {0x1B}, {0x1C}, {0x1D}, {0x1E}, {0x1F}};
    evmone::uint256* top_stack = &stack[stack_size - 1];

    for (std::uint8_t op_code = evmc_opcode::OP_STOP; op_code < evmc_opcode::OP_SELFDESTRUCT; ++op_code) {
        std::optional<TraceMemory> trace_memory;
        copy_memory_offset_len(op_code, top_stack, trace_memory);

        switch (op_code) {
            case evmc_opcode::OP_MSTORE:
            case evmc_opcode::OP_MLOAD:
                CHECK(trace_memory.has_value() == true);
                CHECK(nlohmann::json(trace_memory.value()) == R"({
                    "data":"",
                    "off": 31
                })"_json);
                break;
            case evmc_opcode::OP_MSTORE8:
                CHECK(trace_memory.has_value() == true);
                CHECK(nlohmann::json(trace_memory.value()) == R"({
                    "data":"",
                    "off": 31
                })"_json);
                break;
            case evmc_opcode::OP_RETURNDATACOPY:
            case evmc_opcode::OP_CALLDATACOPY:
            case evmc_opcode::OP_CODECOPY:
                CHECK(trace_memory.has_value() == true);
                CHECK(nlohmann::json(trace_memory.value()) == R"({
                    "data":"",
                    "off": 31
                })"_json);
                break;
            case evmc_opcode::OP_STATICCALL:
            case evmc_opcode::OP_DELEGATECALL:
                CHECK(trace_memory.has_value() == true);
                CHECK(nlohmann::json(trace_memory.value()) == R"({
                    "data":"",
                    "off": 27
                })"_json);
                break;
            case evmc_opcode::OP_CALL:
            case evmc_opcode::OP_CALLCODE:
                CHECK(trace_memory.has_value() == true);
                CHECK(nlohmann::json(trace_memory.value()) == R"({
                    "data":"",
                    "off": 26
                })"_json);
                break;
            case evmc_opcode::OP_CREATE:
            case evmc_opcode::OP_CREATE2:
                CHECK(trace_memory.has_value() == true);
                CHECK(nlohmann::json(trace_memory.value()) == R"({
                    "data":"",
                    "off": 0
                })"_json);
                break;
            default:
                CHECK(trace_memory.has_value() == false);
                break;
        }
    }
}

TEST_CASE("push_memory_offset_len") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    const std::size_t stack_size{32};
    evmone::uint256 stack[stack_size] = {
        {0x00}, {0x01}, {0x02}, {0x03}, {0x04}, {0x05}, {0x06}, {0x07}, {0x08}, {0x09}, {0x0A}, {0x0B}, {0x0C}, {0x0D}, {0x0E}, {0x0F}, {0x10}, {0x11}, {0x12}, {0x13}, {0x14}, {0x15}, {0x16}, {0x17}, {0x18}, {0x19}, {0x1A}, {0x1B}, {0x1C}, {0x1D}, {0x1E}, {0x1F}};
    evmone::uint256* top_stack = &stack[stack_size - 1];

    for (std::uint8_t op_code = evmc_opcode::OP_STOP; op_code < evmc_opcode::OP_SELFDESTRUCT; ++op_code) {
        std::stack<TraceMemory> tms;
        push_memory_offset_len(op_code, top_stack, tms);

        switch (op_code) {
            case evmc_opcode::OP_STATICCALL:
            case evmc_opcode::OP_DELEGATECALL:
                CHECK(tms.size() == 1);
                CHECK(nlohmann::json(tms.top()) == R"({
                    "data":"",
                    "off": 27
                })"_json);
                break;
            case evmc_opcode::OP_CALL:
            case evmc_opcode::OP_CALLCODE:
                CHECK(tms.size() == 1);
                CHECK(nlohmann::json(tms.top()) == R"({
                    "data":"",
                    "off": 26
                })"_json);
                break;
            case evmc_opcode::OP_CREATE:
            case evmc_opcode::OP_CREATE2:
                CHECK(tms.size() == 1);
                CHECK(nlohmann::json(tms.top()) == R"({
                    "data":"",
                    "off": 0
                })"_json);
                break;
            default:
                CHECK(tms.empty());
                break;
        }
    }
}

TEST_CASE("to_string") {
    SECTION("value == 0") {
        auto out = to_string(intx::uint256{0});
        CHECK(out == "0x0000000000000000000000000000000000000000000000000000000000000000");
    }
    SECTION("value == 1") {
        auto out = to_string(intx::uint256{1});
        CHECK(out == "0x0000000000000000000000000000000000000000000000000000000000000001");
    }
    SECTION("value == 1") {
        auto out = to_string(intx::uint256{0xdeadbeaf});
        CHECK(out == "0x00000000000000000000000000000000000000000000000000000000deadbeaf");
    }
}

TEST_CASE("TraceConfig") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    SECTION("dump on stream") {
        TraceConfig config{true, false, true};

        std::ostringstream os;
        os << config;
        CHECK(os.str() == "vmTrace: true Trace: false stateDiff: true");
    }
    SECTION("json deserialization: empty") {
        nlohmann::json json = R"([])"_json;

        TraceConfig config;
        from_json(json, config);

        CHECK(config.trace == false);
        CHECK(config.vm_trace == false);
        CHECK(config.state_diff == false);
    }
    SECTION("json deserialization: full") {
        nlohmann::json json = R"(["trace", "vmTrace", "stateDiff"])"_json;

        TraceConfig config;
        from_json(json, config);

        CHECK(config.trace == true);
        CHECK(config.vm_trace == true);
        CHECK(config.state_diff == true);
    }
}

TEST_CASE("TraceFilter") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    SECTION("dump on stream: simple") {
        TraceFilter config;

        std::ostringstream os;
        os << config;

        CHECK(os.str() == "from_block: 0x0, to_block: latest, after: 0, count: 4294967295");
    }
    SECTION("dump on stream: full") {
        TraceFilter config;
        config.from_addresses.push_back(0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address);
        config.to_addresses.push_back(0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7031_address);
        config.mode = "union";
        std::ostringstream os;
        os << config;

        CHECK(os.str() ==
              "from_block: 0x0, to_block: latest, from_addresses: [0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030, ], "
              "to_addresses: [0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7031, ], mode: union, after: 0, count: 4294967295");
    }
    SECTION("json deserialization: simple") {
        nlohmann::json json = R"({
          "after": 18,
          "count": 10,
          "fromBlock": "0x6DDD00",
          "toBlock": "latest"
        })"_json;

        TraceFilter config = json;

        CHECK(config.after == 18);
        CHECK(config.count == 10);
        CHECK(config.from_block.is_number() == true);
        CHECK(config.from_block.number() == 0x6DDD00);
        CHECK(config.to_block.is_tag() == true);
        CHECK(config.to_block.tag() == "latest");
        CHECK(config.from_addresses.empty());
        CHECK(config.to_addresses.empty());
        CHECK(!config.mode);
    }
    SECTION("json deserialization: full") {
        nlohmann::json json = R"({
          "after": 18,
          "count": 10,
          "fromAddress": [
            "0xd05526a73bf45dadf7f9a99dcceac23c2d43c6c7"
          ],
          "fromBlock": "0x6DDD00",
          "toAddress": [
            "0x11fe4b6ae13d2a6055c8d9cf65c55bac32b5d844"
          ],
          "toBlock": "latest",
          "mode": "union"
        })"_json;

        TraceFilter config;
        from_json(json, config);

        CHECK(config.after == 18);
        CHECK(config.count == 10);
        CHECK(config.from_block.is_number() == true);
        CHECK(config.from_block.number() == 0x6DDD00);
        CHECK(config.to_block.is_tag() == true);
        CHECK(config.from_addresses.size() == 1);
        CHECK(config.from_addresses[0] == 0xd05526a73bf45dadf7f9a99dcceac23c2d43c6c7_address);
        CHECK(config.to_addresses.size() == 1);
        CHECK(config.to_addresses[0] == 0x11fe4b6ae13d2a6055c8d9cf65c55bac32b5d844_address);
        CHECK(config.mode);
        CHECK(config.mode.value() == "union");
    }
}

TEST_CASE("TraceCall") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    SECTION("json deserialization") {
        nlohmann::json json = R"([
            {
                "from": "0x8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9",
                "to": "0x5e1f0c9ddbe3cb57b80c933fab5151627d7966fa",
                "gas": "0x7530",
                "gasPrice": "0x3b9aca00",
                "value": "0x2FAF080",
                "data": "0x01"
            },
            ["trace", "vmTrace", "stateDiff"]
       ])"_json;

        TraceCall trace_call;
        from_json(json, trace_call);

        CHECK(trace_call.call.from == 0x8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9_address);
        CHECK(trace_call.call.to == 0x5e1f0c9ddbe3cb57b80c933fab5151627d7966fa_address);
        CHECK(trace_call.call.gas == 0x7530);
        CHECK(trace_call.call.gas_price == 0x3b9aca00);
        CHECK(trace_call.call.value == 0x2FAF080);
        CHECK(trace_call.call.data == *silkworm::from_hex("01"));

        CHECK(trace_call.trace_config.trace == true);
        CHECK(trace_call.trace_config.vm_trace == true);
        CHECK(trace_call.trace_config.state_diff == true);
    }
}

TEST_CASE("TraceCallTraces: json serialization") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    TraceCallTraces tct;
    tct.output = "0xdeadbeaf";

    SECTION("with transaction_hash") {
        tct.transaction_hash = 0xe0d4933284f1254835aac8823535278f0eb9608b137266cf3d3d8df8240bbe48_bytes32;
        CHECK(nlohmann::json(tct) == R"({
            "output": "0xdeadbeaf",
            "stateDiff": null,
            "trace": [],
            "transactionHash": "0xe0d4933284f1254835aac8823535278f0eb9608b137266cf3d3d8df8240bbe48",
            "vmTrace": null
        })"_json);
    }

    SECTION("with state_diff") {
        tct.state_diff = StateDiff{};
        CHECK(nlohmann::json(tct) == R"({
            "output": "0xdeadbeaf",
            "stateDiff": {},
            "trace": [],
            "vmTrace": null
        })"_json);
    }

    SECTION("with trace") {
        tct.trace.push_back(Trace{});
        CHECK(nlohmann::json(tct) == R"({
            "output": "0xdeadbeaf",
            "stateDiff": null,
            "trace": [
                {
                "action": {
                    "from": "0x0000000000000000000000000000000000000000",
                    "gas": "0x0",
                    "value": "0x0"
                },
                "result": null,
                "subtraces": 0,
                "traceAddress": [],
                "type": ""
                }
            ],
            "vmTrace": null
        })"_json);
    }

    SECTION("with vm_trace") {
        tct.vm_trace = VmTrace{};
        CHECK(nlohmann::json(tct) == R"({
            "output": "0xdeadbeaf",
            "stateDiff": null,
            "trace": [],
            "vmTrace": {
                "code": "0x",
                "ops": []
            }
        })"_json);
    }
}

TEST_CASE("TraceCallResult: json serialization") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    TraceCallResult tcr;

    SECTION("with traces") {
        tcr.traces = TraceCallTraces{};
        CHECK(nlohmann::json(tcr) == R"({
            "output": "0x",
            "stateDiff": null,
            "trace": [],
            "vmTrace": null
        })"_json);
    }
}

TEST_CASE("TraceManyCallResult: json serialization") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    TraceManyCallResult tmcr;

    SECTION("with traces") {
        tmcr.traces.push_back(TraceCallTraces{});
        CHECK(nlohmann::json(tmcr) == R"([
            {
                "output": "0x",
                "stateDiff": null,
                "trace": [],
                "vmTrace": null
            }
        ])"_json);
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::trace
