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

#include "evm_debug.hpp"

#include <string>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <catch2/catch.hpp>
#include <gmock/gmock.h>

#include <silkworm/db/tables.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/storage/remote_chain_storage.hpp>
#include <silkworm/rpc/test/context_test_base.hpp>
#include <silkworm/rpc/test/dummy_transaction.hpp>
#include <silkworm/rpc/test/mock_back_end.hpp>
#include <silkworm/rpc/test/mock_block_cache.hpp>
#include <silkworm/rpc/test/mock_cursor.hpp>
#include <silkworm/rpc/test/mock_database_reader.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm::rpc::debug {

using testing::InvokeWithoutArgs;

static Bytes kZeroKey{*silkworm::from_hex("0000000000000000")};
static Bytes kZeroHeader{*silkworm::from_hex("bf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a")};

static Bytes kConfigKey{
    *silkworm::from_hex("bf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a")};
static Bytes kConfigValue{*silkworm::from_hex(
    "7b22436861696e4e616d65223a22676f65726c69222c22636861696e4964223a352c22636f6e73656e737573223a22636c69717565222c2268"
    "6f6d657374656164426c6f636b223a302c2264616f466f726b537570706f7274223a747275652c22656970313530426c6f636b223a302c2265"
    "697031353048617368223a22307830303030303030303030303030303030303030303030303030303030303030303030303030303030303030"
    "303030303030303030303030303030303030303030222c22656970313535426c6f636b223a302c22656970313538426c6f636b223a302c2262"
    "797a616e7469756d426c6f636b223a302c22636f6e7374616e74696e6f706c65426c6f636b223a302c2270657465727362757267426c6f636b"
    "223a302c22697374616e62756c426c6f636b223a313536313635312c226265726c696e426c6f636b223a343436303634342c226c6f6e646f6e"
    "426c6f636b223a353036323630352c22636c69717565223a7b22706572696f64223a31352c2265706f6368223a33303030307d7d")};

struct DebugExecutorTest : public test::ContextTestBase {
};

class TestDebugExecutor : DebugExecutor {
  public:
    explicit TestDebugExecutor(
        const core::rawdb::DatabaseReader& database_reader,
        BlockCache& block_cache,
        boost::asio::thread_pool& workers,
        ethdb::Transaction& tx,
        DebugConfig config = {})
        : DebugExecutor(database_reader, block_cache, workers, tx, config) {}
    ~TestDebugExecutor() override = default;

    TestDebugExecutor(const TestDebugExecutor&) = delete;
    TestDebugExecutor& operator=(const TestDebugExecutor&) = delete;

    Task<void> execute(json::Stream& stream, const ChainStorage& storage, const silkworm::Block& block, const Call& call) {
        return DebugExecutor::execute(stream, storage, block, call);
    }
};

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(DebugExecutorTest, "DebugExecutor::execute precompiled") {
    static Bytes kAccountHistoryKey1{*silkworm::from_hex("0a6bb546b9208cfab9e8fa2b9b2c042b18df703000000000009db707")};
    static Bytes kAccountHistoryKey2{*silkworm::from_hex("000000000000000000000000000000000000000900000000009db707")};
    static Bytes kAccountHistoryKey3{*silkworm::from_hex("000000000000000000000000000000000000000000000000009db707")};

    static Bytes kPlainStateKey1{*silkworm::from_hex("0a6bb546b9208cfab9e8fa2b9b2c042b18df7030")};
    static Bytes kPlainStateKey2{*silkworm::from_hex("0000000000000000000000000000000000000009")};
    static Bytes kPlainStateKey3{*silkworm::from_hex("000000000000000000000000000000000000000")};

    static Bytes kPlainStateValue1{
        *silkworm::from_hex("0f010203ed03e8010520f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239")};

    test::MockBlockCache cache;
    test::MockDatabaseReader db_reader;
    boost::asio::thread_pool workers{1};

    ClientContextPool pool{1};
    pool.start();
    boost::asio::any_io_executor io_executor = pool.next_io_context().get_executor();

    StringWriter writer(4096);
    json::Stream stream(io_executor, writer);

    SECTION("precompiled contract failure") {
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{Bytes{}, Bytes{}};
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kPlainStateValue1;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, Bytes{}};
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, Bytes{}};
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey3}))
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

        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        TestDebugExecutor executor{db_reader, cache, workers, tx};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{db_reader, backend.get()};

        stream.open_object();
        spawn_and_wait(executor.execute(stream, storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
            "failed":true,
            "gas":50000,
            "returnValue":"",
            "structLogs":[]
        })"_json);
    }
}

TEST_CASE_METHOD(DebugExecutorTest, "DebugExecutor::execute call 1") {
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

    static Bytes kAccountChangeSetKey1{*silkworm::from_hex("00000000005279ab")};
    static Bytes kAccountChangeSetSubkey1{*silkworm::from_hex("e0a2bd4258d2768837baa26a28fe71dc079f84c7")};
    static Bytes kAccountChangeSetValue1{*silkworm::from_hex("030203430b141e903194951083c424fd")};

    static Bytes kAccountChangeSetKey2{*silkworm::from_hex("0000000000532b9f")};
    static Bytes kAccountChangeSetSubKey2{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes kAccountChangeSetValue2{*silkworm::from_hex("020944ed67f28fd50bb8e9")};

    static Bytes kPlainStateKey1{*silkworm::from_hex("e0a2bd4258d2768837baa26a28fe71dc079f84c7")};
    static Bytes kPlainStateKey2{*silkworm::from_hex("52728289eba496b6080d57d0250a90663a07e556")};

    test::MockBlockCache cache;
    test::MockDatabaseReader db_reader;
    boost::asio::thread_pool workers{1};

    ClientContextPool pool{1};
    pool.start();
    boost::asio::any_io_executor io_executor = pool.next_io_context().get_executor();

    StringWriter writer(4096);
    json::Stream stream(io_executor, writer);

    SECTION("Call: failed with intrinsic gas too low") {
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey1}))
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

        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        TestDebugExecutor executor{db_reader, cache, workers, tx};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{db_reader, backend.get()};

        stream.open_object();
        spawn_and_wait(executor.execute(stream, storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
            "failed": true,
            "structLogs":[]
        })"_json);
    }

    SECTION("Call: full output") {
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1}, silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue1;
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2}, silkworm::ByteView{kAccountChangeSetSubKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue2;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
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

        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        TestDebugExecutor executor{db_reader, cache, workers, tx};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{db_reader, backend.get()};

        stream.open_object();
        spawn_and_wait(executor.execute(stream, storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
            "failed": false,
            "gas": 75178,
            "returnValue": "",
            "structLogs": [
                {
                    "depth": 1,
                    "gas": 65864,
                    "gasCost": 3,
                    "memory": [],
                    "op": "PUSH1",
                    "pc": 0,
                    "stack": []
                },
                {
                    "depth": 1,
                    "gas": 65861,
                    "gasCost": 3,
                    "memory": [],
                    "op": "PUSH1",
                    "pc": 2,
                    "stack": [
                        "0x2a"
                    ]
                },
                {
                    "depth": 1,
                    "gas": 65858,
                    "gasCost": 22100,
                    "memory": [],
                    "op": "SSTORE",
                    "pc": 4,
                    "stack": [
                        "0x2a",
                        "0x0"
                    ],
                    "storage": {
                        "0000000000000000000000000000000000000000000000000000000000000000": "000000000000000000000000000000000000000000000000000000000000002a"
                    }
                },
                {
                    "depth": 1,
                    "gas": 43758,
                    "gasCost": 0,
                    "memory": [],
                    "op": "STOP",
                    "pc": 5,
                    "stack": []
                }
            ]
        })"_json);
    }

    SECTION("Call: no stack") {
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1}, silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue1;
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2}, silkworm::ByteView{kAccountChangeSetSubKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue2;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
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

        DebugConfig config{false, false, true};
        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        TestDebugExecutor executor{db_reader, cache, workers, tx, config};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{db_reader, backend.get()};

        stream.open_object();
        spawn_and_wait(executor.execute(stream, storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
            "failed": false,
            "gas": 75178,
            "returnValue": "",
            "structLogs": [
                {
                    "depth": 1,
                    "gas": 65864,
                    "gasCost": 3,
                    "memory": [],
                    "op": "PUSH1",
                    "pc": 0
                },
                {
                    "depth": 1,
                    "gas": 65861,
                    "gasCost": 3,
                    "memory": [],
                    "op": "PUSH1",
                    "pc": 2
                },
                {
                    "depth": 1,
                    "gas": 65858,
                    "gasCost": 22100,
                    "memory": [],
                    "op": "SSTORE",
                    "pc": 4,
                    "storage": {
                        "0000000000000000000000000000000000000000000000000000000000000000": "000000000000000000000000000000000000000000000000000000000000002a"
                    }
                },
                {
                    "depth": 1,
                    "gas": 43758,
                    "gasCost": 0,
                    "memory": [],
                    "op": "STOP",
                    "pc": 5
                }
            ]
        })"_json);
    }

    SECTION("Call: no memory") {
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1}, silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue1;
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2}, silkworm::ByteView{kAccountChangeSetSubKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue2;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
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

        DebugConfig config{false, true, false};
        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        TestDebugExecutor executor{db_reader, cache, workers, tx, config};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{db_reader, backend.get()};

        stream.open_object();
        spawn_and_wait(executor.execute(stream, storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
            "failed": false,
            "gas": 75178,
            "returnValue": "",
            "structLogs": [
                {
                    "depth": 1,
                    "gas": 65864,
                    "gasCost": 3,
                    "op": "PUSH1",
                    "pc": 0,
                    "stack": []
                },
                {
                    "depth": 1,
                    "gas": 65861,
                    "gasCost": 3,
                    "op": "PUSH1",
                    "pc": 2,
                    "stack": [
                        "0x2a"
                    ]
                },
                {
                    "depth": 1,
                    "gas": 65858,
                    "gasCost": 22100,
                    "op": "SSTORE",
                    "pc": 4,
                    "stack": [
                        "0x2a",
                        "0x0"
                    ],
                    "storage": {
                        "0000000000000000000000000000000000000000000000000000000000000000": "000000000000000000000000000000000000000000000000000000000000002a"
                    }
                },
                {
                    "depth": 1,
                    "gas": 43758,
                    "gasCost": 0,
                    "op": "STOP",
                    "pc": 5,
                    "stack": []
                }
            ]
        })"_json);
    }

    SECTION("Call: no storage") {
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1}, silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue1;
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2}, silkworm::ByteView{kAccountChangeSetSubKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue2;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
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

        DebugConfig config{true, false, false};
        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        TestDebugExecutor executor{db_reader, cache, workers, tx, config};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{db_reader, backend.get()};

        stream.open_object();
        spawn_and_wait(executor.execute(stream, storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
            "failed": false,
            "gas": 75178,
            "returnValue": "",
            "structLogs": [
                {
                    "depth": 1,
                    "gas": 65864,
                    "gasCost": 3,
                    "memory": [],
                    "op": "PUSH1",
                    "pc": 0,
                    "stack": []
                },
                {
                    "depth": 1,
                    "gas": 65861,
                    "gasCost": 3,
                    "memory": [],
                    "op": "PUSH1",
                    "pc": 2,
                    "stack": [
                        "0x2a"
                    ]
                },
                {
                    "depth": 1,
                    "gas": 65858,
                    "gasCost": 22100,
                    "memory": [],
                    "op": "SSTORE",
                    "pc": 4,
                    "stack": [
                        "0x2a",
                        "0x0"
                    ]
                },
                {
                    "depth": 1,
                    "gas": 43758,
                    "gasCost": 0,
                    "memory": [],
                    "op": "STOP",
                    "pc": 5,
                    "stack": []
                }
            ]
        })"_json);
    }

    SECTION("Call: no stack, memory and storage") {
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1}, silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue1;
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2}, silkworm::ByteView{kAccountChangeSetSubKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue2;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
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

        DebugConfig config{true, true, true};
        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        TestDebugExecutor executor{db_reader, cache, workers, tx, config};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{db_reader, backend.get()};

        stream.open_object();
        spawn_and_wait(executor.execute(stream, storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
            "failed": false,
            "gas": 75178,
            "returnValue": "",
            "structLogs": [
                {
                    "depth": 1,
                    "gas": 65864,
                    "gasCost": 3,
                    "op": "PUSH1",
                    "pc": 0
                },
                {
                    "depth": 1,
                    "gas": 65861,
                    "gasCost": 3,
                    "op": "PUSH1",
                    "pc": 2
                },
                {
                    "depth": 1,
                    "gas": 65858,
                    "gasCost": 22100,
                    "op": "SSTORE",
                    "pc": 4
                },
                {
                    "depth": 1,
                    "gas": 43758,
                    "gasCost": 0,
                    "op": "STOP",
                    "pc": 5
                }
            ]
        })"_json);
    }

    SECTION("Call with stream") {
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1}, silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue1;
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2}, silkworm::ByteView{kAccountChangeSetSubKey2}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return kAccountChangeSetValue2;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey2}))
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

        DebugConfig config{true, true, true};
        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        TestDebugExecutor executor{db_reader, cache, workers, tx, config};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{db_reader, backend.get()};

        stream.open_object();
        spawn_and_wait(executor.execute(stream, storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
            "failed": false,
            "gas": 75178,
            "returnValue": "",
            "structLogs": [
                {
                    "depth": 1,
                    "gas": 65864,
                    "gasCost": 3,
                    "op": "PUSH1",
                    "pc": 0
                },
                {
                    "depth": 1,
                    "gas": 65861,
                    "gasCost": 3,
                    "op": "PUSH1",
                    "pc": 2
                },
                {
                    "depth": 1,
                    "gas": 65858,
                    "gasCost": 22100,
                    "op": "SSTORE",
                    "pc": 4
                },
                {
                    "depth": 1,
                    "gas": 43758,
                    "gasCost": 0,
                    "op": "STOP",
                    "pc": 5
                }
            ]
        })"_json);
    }
}

TEST_CASE_METHOD(DebugExecutorTest, "DebugExecutor::execute call 2") {
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

    static Bytes kAccountChangeSetKey3{*silkworm::from_hex("000000000044589b")};
    static Bytes kAccountChangeSetSubkey3{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes kAccountChangeSetValue3{*silkworm::from_hex("02094165832d46fa1082db")};

    test::MockBlockCache cache;
    test::MockDatabaseReader db_reader;
    boost::asio::thread_pool workers{1};

    ClientContextPool pool{1};
    pool.start();
    boost::asio::any_io_executor io_executor = pool.next_io_context().get_executor();

    StringWriter writer(4096);
    json::Stream stream(io_executor, writer);

    SECTION("Call: TO present") {
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kZeroHeader;
            }));
        EXPECT_CALL(db_reader, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
            }));
        EXPECT_CALL(db_reader,
                    get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1},
                                   silkworm::ByteView{kAccountChangeSetSubkey1}))
            .WillOnce(InvokeWithoutArgs(
                []() -> Task<std::optional<Bytes>> {
                    co_return kAccountChangeSetValue1;
                }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
            }));
        EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
            }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2},
                                              silkworm::ByteView{kAccountChangeSetSubkey2}))
            .WillOnce(InvokeWithoutArgs(
                []() -> Task<std::optional<Bytes>> {
                    co_return kAccountChangeSetValue2;
                }));
        EXPECT_CALL(db_reader, get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey3},
                                              silkworm::ByteView{kAccountChangeSetSubkey3}))
            .WillOnce(InvokeWithoutArgs(
                []() -> Task<std::optional<Bytes>> {
                    co_return kAccountChangeSetValue3;
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

        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        TestDebugExecutor executor{db_reader, cache, workers, tx};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{db_reader, backend.get()};

        stream.open_object();
        spawn_and_wait(executor.execute(stream, storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
            "failed": false,
            "gas": 21004,
            "returnValue": "",
            "structLogs": []
        })"_json);
    }
}

TEST_CASE_METHOD(DebugExecutorTest, "DebugExecutor::execute call with error") {
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

    static Bytes kPlainStateKey{*silkworm::from_hex("6951c35e335fa18c97cb207119133cd8009580cd")};

    static Bytes kAccountChangeSetKey{*silkworm::from_hex("00000000005279ad")};
    static Bytes kAccountChangeSetSubkey{*silkworm::from_hex("578f0a154b23be77fc2033197fbc775637648ad4")};
    static Bytes kAccountChangeSetValue{*silkworm::from_hex("03012f090207fbc719f215d705")};

    static Bytes kAccountChangeSetKey1{*silkworm::from_hex("00000000005EF618")};
    static Bytes kAccountChangeSetSubkey1{*silkworm::from_hex("6951c35e335fa18c97cb207119133cd8009580cd")};
    static Bytes kAccountChangeSetValue1{*silkworm::from_hex("00000000005279a8")};

    static Bytes kAccountChangeSetKey2{*silkworm::from_hex("0000000000532b9f")};
    static Bytes kAccountChangeSetSubkey2{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes kAccountChangeSetValue2{*silkworm::from_hex("020944ed67f28fd50bb8e9")};

    test::MockBlockCache cache;
    test::MockDatabaseReader db_reader;
    boost::asio::thread_pool workers{1};

    ClientContextPool pool{1};
    pool.start();
    boost::asio::any_io_executor io_executor = pool.next_io_context().get_executor();

    StringWriter writer(4096);
    json::Stream stream(io_executor, writer);

    EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashesName, silkworm::ByteView{kZeroKey}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kZeroHeader;
        }));
    EXPECT_CALL(db_reader, get_one(db::table::kConfigName, silkworm::ByteView{kConfigKey}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kConfigValue;
        }));
    EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey1}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey1, kAccountHistoryValue1};
        }));
    EXPECT_CALL(db_reader,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey},
                               silkworm::ByteView{kAccountChangeSetSubkey}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue;
        }));
    EXPECT_CALL(db_reader,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey1},
                               silkworm::ByteView{kAccountChangeSetSubkey1}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue1;
        }));
    EXPECT_CALL(db_reader,
                get_both_range(db::table::kAccountChangeSetName, silkworm::ByteView{kAccountChangeSetKey2},
                               silkworm::ByteView{kAccountChangeSetSubkey2}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
            co_return kAccountChangeSetValue2;
        }));
    EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey2}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey2, kAccountHistoryValue2};
        }));
    EXPECT_CALL(db_reader, get(db::table::kAccountHistoryName, silkworm::ByteView{kAccountHistoryKey3}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kAccountHistoryKey3, kAccountHistoryValue3};
        }));
    EXPECT_CALL(db_reader, get_one(db::table::kPlainStateName, silkworm::ByteView{kPlainStateKey}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
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

    std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
    test::DummyTransaction tx{0, mock_cursor};
    TestDebugExecutor executor{db_reader, cache, workers, tx};
    const auto backend = std::make_unique<test::BackEndMock>();
    const RemoteChainStorage storage{db_reader, backend.get()};

    stream.open_object();
    spawn_and_wait(executor.execute(stream, storage, block, call));
    stream.close_object();
    spawn_and_wait(stream.close());

    nlohmann::json json = nlohmann::json::parse(writer.get_content());

    CHECK(json == R"({
        "failed": true,
        "gas": 211190,
        "returnValue": "",
        "structLogs": [
            {
                "depth": 1,
                "gas": 156082,
                "gasCost": 2,
                "memory": [],
                "op": "COINBASE",
                "pc": 0,
                "stack": []
            },
            {
                "depth": 1,
                "gas": 156080,
                "gasCost": 0,
                "memory": [],
                "op": "opcode 0x4b not defined",
                "pc": 1,
                "stack": [
                    "0x0"
                ]
            }
        ]
    })"_json);
}

TEST_CASE_METHOD(DebugExecutorTest, "DebugConfig") {
    SECTION("json deserialization") {
        nlohmann::json json = R"({
            "disableStorage": true,
            "disableMemory": false,
            "disableStack": true
            })"_json;

        DebugConfig config;
        from_json(json, config);

        CHECK(config.disableStorage == true);
        CHECK(config.disableMemory == false);
        CHECK(config.disableStack == true);
    }
    SECTION("dump on stream") {
        DebugConfig config{true, false, true};

        std::ostringstream os;
        os << config;
        CHECK(os.str() == "disableStorage: true disableMemory: false disableStack: true");
    }
}

TEST_CASE("uint256_to_hex", "evmone::uint256") {
    SECTION("test 1") {
        evmone::uint256 v{0xB0A0};
        const std::string intx_hex{"0x" + intx::to_string(v, 16)};

        std::string hex{uint256_to_hex(v)};

        CHECK(intx_hex == hex);
    }
    SECTION("test 2") {
        evmone::uint256 v{0xCB0A0};
        const std::string intx_hex{"0x" + intx::to_string(v, 16)};

        std::string hex{uint256_to_hex(v)};

        CHECK(intx_hex == hex);
    }
}

#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::debug
