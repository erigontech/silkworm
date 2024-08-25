/*
   Copyright 2024 The Silkworm Authors

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

#include "web_seed_client.hpp"

#include <boost/system/system_error.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <gmock/gmock.h>
#include <libtorrent/hex.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>
#include <silkworm/infra/test_util/hex.hpp>

namespace silkworm::snapshots::bittorrent {

using testing::_;
using testing::InvokeWithoutArgs;

//! WebSeedClient with protected methods exposed for test
class WebSeedClient_ForTest : public WebSeedClient {
  public:
    using WebSeedClient::build_list_of_torrents;
    using WebSeedClient::download_and_filter_all_torrents;
    using WebSeedClient::download_from_provider;
    using WebSeedClient::is_caplin_segment;
    using WebSeedClient::is_whitelisted;
    using WebSeedClient::validate_torrent_file;
    using WebSeedClient::WebSeedClient;  // NOLINT(*-rvalue-reference-param-not-moved)
};

TEST_CASE("WebSeedClient_ForTest::is_caplin_segment", "[db][snapshot][bittorrent]") {
    CHECK(!WebSeedClient_ForTest::is_caplin_segment("v1-000000-000500-bodies.seg"));
    CHECK(!WebSeedClient_ForTest::is_caplin_segment("v1-000000-000500-headers.seg"));
    CHECK(!WebSeedClient_ForTest::is_caplin_segment("v1-000000-000500-transactions.seg"));

    CHECK(WebSeedClient_ForTest::is_caplin_segment("v1-000000-000100-beaconblocks.seg"));
}

//! Content for manifest file containing one torrent file
static constexpr auto kValidManifestContent{
    "v1-018700-018800-bodies.seg.torrent\n"sv};

//! Hexadecimal content for torrent file 'v1-018700-018800-bodies.seg'
static constexpr auto kValidTorrentContent{
    "6431333A616E6E6F756E63652D6C6973746C6C34323A7564703A2F2F74726163"
    "6B65722E6F70656E747261636B722E6F72673A313333372F616E6E6F756E6365"
    "34363A7564703A2F2F747261636B65722E6F70656E626974746F7272656E742E"
    "636F6D3A363936392F616E6E6F756E636534313A7564703A2F2F6F70656E7472"
    "61636B65722E6932702E726F636B733A363936392F616E6E6F756E636534313A"
    "7564703A2F2F747261636B65722E746F7272656E742E65752E6F72673A343531"
    "2F616E6E6F756E636533333A7564703A2F2F6F70656E2E737465616C74682E73"
    "693A38302F616E6E6F756E6365656531303A63726561746564206279363A6572"
    "69676F6E31333A6372656174696F6E2064617465693137313337373936393265"
    "343A696E666F64363A6C656E67746869333739393037383165343A6E616D6532"
    "373A76312D3031383730302D3031383830302D626F646965732E73656731323A"
    "7069656365206C656E677468693230393731353265363A706965636573333830"
    "3A19F52F24A5723B7E6E832E74ACC84BA08DB647FB86EF863C677D8E34E8B60E"
    "1EF0AE6193FD18718437F8055D768F3C48E5B3A955736DD61B8ECEA7EB469BDF"
    "8093F83B95FD50D87385BDD6EEBB57FB12F6D11DB7B7442349447D0B30627A4D"
    "FA754F398006A8F919C09346DE107A5506CF7887BB9649A7430F70A413F596DE"
    "769E096E0561A85D830E38613E99528319849F58FC2D4C06261901A3419069B8"
    "BE706D073DC3DC86A836F747B8D46609328E62F93D3FEF8C9A86BC9CB932CE7D"
    "7DF35DC81ECBB9E150214A1FE5DCA5903FD37C20FBDFF5C4C739F908A602C655"
    "9DDC2C29204037E74F5869B659BCD751B2CE9F8160CFCA80C7BBA61A4A3A3501"
    "2AFDD267C501F03B918564D52D956126B6987F2237D1C6340875317890F6E8AC"
    "050DBC17CCF24DB11105F97FA191DAB57C4B76E82D876E25ED5AC23621B1B686"
    "BE930516DF5D4B0809F6335A3F78CFD3352320FD41514FDA99BED7E565143FF8"
    "D45B74826E9E6D24B6F82CE88DDD8BC2C3BF9028FF56CE668551DB6EDC6565"sv};
static const std::string kValidTorrentContentAscii{test_util::ascii_from_hex(kValidTorrentContent)};

struct WebSessionMock : public WebSession {
    MOCK_METHOD((Task<WebSession::StringResponse>), https_get, (const urls::url&, std::string_view), (const, override));
};

struct WebSeedClientTest : public test_util::ContextTestBase {
    inline static const auto kErigon2Snapshots{"https://erigon2-v1-snapshots-mainnet.erigon.network"};
    inline static const boost::urls::url kErigon2SnapshotsUrl{kErigon2Snapshots};
    snapshots::Config known_config{snapshots::Config::lookup_known_config(/*chain_id=*/1, /*whitelist=*/{})};
    std::unique_ptr<WebSessionMock> session{std::make_unique<WebSessionMock>()};
    WebSeedClient_ForTest client{{kErigon2Snapshots}, known_config.preverified_snapshots()};
};

TEST_CASE("WebSeedClient_ForTest::WebSeedClient_ForTest", "[db][snapshot][bittorrent]") {
    PreverifiedList preverified_torrent_list;
    WebSeedClient_ForTest client{{}, preverified_torrent_list};
}

TEST_CASE_METHOD(WebSeedClientTest, "WebSeedClient_ForTest::discover_torrents", "[db][snapshot][bittorrent]") {
    SECTION("empty") {
        EXPECT_CALL(*session, https_get(kErigon2SnapshotsUrl, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<WebSession::StringResponse> { co_return WebSession::StringResponse{}; }));
        WebSeedClient_ForTest client{std::move(session), {kErigon2Snapshots}, known_config.preverified_snapshots()};
        CHECK(spawn_and_wait(client.discover_torrents()).empty());
    }
    SECTION("invalid manifest") {
        EXPECT_CALL(*session, https_get(kErigon2SnapshotsUrl, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<WebSession::StringResponse> {
                WebSession::StringResponse rsp;
                rsp.body().assign("\000\001");
                co_return rsp;
            }));
        WebSeedClient_ForTest client{std::move(session), {kErigon2Snapshots}, known_config.preverified_snapshots()};
        CHECK(spawn_and_wait(client.discover_torrents()).empty());
    }
    SECTION("valid manifest") {
        EXPECT_CALL(*session, https_get(kErigon2SnapshotsUrl, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<WebSession::StringResponse> {
                WebSession::StringResponse rsp;
                rsp.body().assign(kValidManifestContent);
                co_return rsp;
            }))
            .WillOnce(InvokeWithoutArgs([]() -> Task<WebSession::StringResponse> {
                WebSession::StringResponse rsp;
                rsp.body().assign(kValidTorrentContentAscii);
                co_return rsp;
            }));
        WebSeedClient_ForTest client{std::move(session), {kErigon2Snapshots}, known_config.preverified_snapshots()};
        TorrentInfoPtrList torrent_info_set;
        CHECK_NOTHROW((torrent_info_set = spawn_and_wait(client.discover_torrents())));
        REQUIRE_FALSE(torrent_info_set.empty());
        const TorrentInfoPtr torrent_info = *torrent_info_set.begin();
        CHECK(torrent_info->name() == "v1-018700-018800-bodies.seg");
        CHECK(lt::aux::to_hex(torrent_info->info_hashes().get_best()) == "2501ab81654fd0b234c819fead66ab197f4c0438");
    }
}

TEST_CASE_METHOD(WebSeedClientTest, "WebSeedClient_ForTest::validate_torrent_file", "[db][snapshot][bittorrent]") {
    CHECK(client.validate_torrent_file(kErigon2SnapshotsUrl, "v1-018700-018800-bodies.seg.torrent", kValidTorrentContentAscii));

    CHECK_THROWS_AS(client.validate_torrent_file(kErigon2SnapshotsUrl, "v1-018700-018800-bodies.seg.torrent", ""), boost::system::system_error);
    CHECK_THROWS_AS(client.validate_torrent_file(kErigon2SnapshotsUrl, "v1-018700-018800-bodies.seg.torrent", "AA"), boost::system::system_error);
}

TEST_CASE_METHOD(WebSeedClientTest, "WebSeedClient_ForTest::is_whitelisted", "[db][snapshot][bittorrent]") {
    CHECK(client.is_whitelisted("v1-018700-018800-bodies.seg", "2501ab81654fd0b234c819fead66ab197f4c0438"));
    CHECK(client.is_whitelisted("v1-018700-018800-headers.seg", "5e170d8255c60ac2c9d6b3c42ba016948181425c"));
    CHECK(client.is_whitelisted("v1-018700-018800-transactions.seg", "449df7eafd54da2c3a67db2ed4fb4fee8bae47c5"));

    CHECK_FALSE(client.is_whitelisted("", ""));
    CHECK_FALSE(client.is_whitelisted("v1-018700-018800-bodies2.seg", "2501ab81654fd0b234c819fead66ab197f4c0438"));     // name
    CHECK_FALSE(client.is_whitelisted("v1-018700-018800-bodies.segment", "2501ab81654fd0b234c819fead66ab197f4c0438"));  // suffix
    CHECK_FALSE(client.is_whitelisted("v1-018700-018800-bodies.seg", "1501ab81654fd0b234c819fead66ab197f4c0438"));      // hash
}

}  // namespace silkworm::snapshots::bittorrent
