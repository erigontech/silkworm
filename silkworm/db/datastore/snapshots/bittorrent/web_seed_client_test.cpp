// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "web_seed_client.hpp"

#include <boost/system/system_error.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <gmock/gmock.h>
#include <libtorrent/hex.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/infra/test_util/hex.hpp>
#include <silkworm/infra/test_util/task_runner.hpp>

namespace silkworm::snapshots::bittorrent {

namespace urls = boost::urls;
using testing::_;
using testing::InvokeWithoutArgs;

//! WebSeedClient with protected methods exposed for test
class WebSeedClientForTest : public WebSeedClient {
  public:
    using WebSeedClient::build_list_of_torrents;
    using WebSeedClient::download_and_filter_all_torrents;
    using WebSeedClient::download_from_provider;
    using WebSeedClient::is_whitelisted;
    using WebSeedClient::validate_torrent_file;
    using WebSeedClient::web_session;
    using WebSeedClient::WebSeedClient;  // NOLINT(cppcoreguidelines-rvalue-reference-param-not-moved)
};

//! Content for manifest file containing one torrent file
static constexpr std::string_view kValidManifestContent{
    "v1-010000-010500-bodies.seg.torrent\n"sv};

//! Hexadecimal content for torrent file 'v1-010000-010500-bodies.seg'
static constexpr std::string_view kValidTorrentContent{
    "6431333a616e6e6f756e63652d6c6973746c6c34323a7564703a2f2f74726163"
    "6b65722e6f70656e747261636b722e6f72673a313333372f616e6e6f756e6365"
    "34363a7564703a2f2f747261636b65722e6f70656e626974746f7272656e742e"
    "636f6d3a363936392f616e6e6f756e636534313a7564703a2f2f6f70656e7472"
    "61636b65722e6932702e726f636b733a363936392f616e6e6f756e636534313a"
    "7564703a2f2f747261636b65722e746f7272656e742e65752e6f72673a343531"
    "2f616e6e6f756e636533333a7564703a2f2f6f70656e2e737465616c74682e73"
    "693a38302f616e6e6f756e6365656531303a63726561746564206279363a6572"
    "69676f6e31333a6372656174696f6e2064617465693137313337373930393565"
    "343a696e666f64363a6c656e67746869323030383332393765343a6e616d6532"
    "373a76312d3031303030302d3031303530302d626f646965732e73656731323a"
    "7069656365206c656e677468693230393731353265363a706965636573323030"
    "3ab9c7251af452c58fa73cc3fff451fc1cf0a1ff426629d3ef68cdc7dd52556b"
    "7be3f1192b06cad8fab33f829fea37455bfa00938c85bd03066f2b46d912daf0"
    "3a7b221c47b119f8e64ba40e574e8e0642e5ef9b5e878d60f7ed7737dca3aace"
    "4fd98b8b83d1f5cced97afeb955f4be33aadab9ea8297899a6e81eaf0613d91a"
    "85f5e6028eb05726651320c3e2b8070b98aa6052610de5bcc1cacd6b818b02ed"
    "5f22b6e32a4d3e97d7889eeee487689e4a0116651aecba0609813b273ee92392"
    "7a9c3103df62ab058f6565"sv};
static const std::string kValidTorrentContentAscii{test_util::ascii_from_hex(kValidTorrentContent)};

struct WebSessionMock : public WebSession {
    MOCK_METHOD((Task<WebSession::StringResponse>), https_get, (const urls::url&, std::string_view, const WebSession::HeaderFields&), (const, override));
};

static const std::string kErigon2Snapshots{"https://erigon2-v1-snapshots-mainnet.erigon.network"};
static boost::urls::url make_e2_snapshots_provider_url() {
    return boost::urls::url{kErigon2Snapshots};
}

TEST_CASE("WebSeedClient::WebSeedClient", "[db][snapshot][bittorrent]") {
    WebSeedClientForTest client{{}, {}};
}

TEST_CASE("WebSeedClient::discover_torrents", "[db][snapshot][bittorrent]") {
    test_util::TaskRunner task_runner;
    static const Whitelist kWhitelist = {{"v1-010000-010500-bodies.seg", "542b3f77a2f3c4b9d8a4085d838bdd1b14043f3b"}};
    WebSeedClientForTest ws_client{std::make_unique<WebSessionMock>(), {kErigon2Snapshots}, kWhitelist};
    auto& session = dynamic_cast<WebSessionMock&>(ws_client.web_session());

    SECTION("empty") {
        EXPECT_CALL(session, https_get(make_e2_snapshots_provider_url(), _, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<WebSession::StringResponse> { co_return WebSession::StringResponse{}; }));
        TorrentInfoPtrList torrent_info_set = task_runner.run(ws_client.discover_torrents());
        CHECK(torrent_info_set.empty());
    }

    SECTION("invalid manifest") {
        EXPECT_CALL(session, https_get(make_e2_snapshots_provider_url(), _, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<WebSession::StringResponse> {
                WebSession::StringResponse rsp;
                rsp.body().assign("\000\001");
                co_return rsp;
            }));
        TorrentInfoPtrList torrent_info_set = task_runner.run(ws_client.discover_torrents());
        CHECK(torrent_info_set.empty());
    }

    SECTION("valid manifest") {
        EXPECT_CALL(session, https_get(make_e2_snapshots_provider_url(), _, _))
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
        TorrentInfoPtrList torrent_info_set = task_runner.run(ws_client.discover_torrents());
        REQUIRE_FALSE(torrent_info_set.empty());
        const TorrentInfoPtr torrent_info = *torrent_info_set.begin();
        CHECK(torrent_info->name() == "v1-010000-010500-bodies.seg");
        CHECK(lt::aux::to_hex(torrent_info->info_hashes().get_best()) == "542b3f77a2f3c4b9d8a4085d838bdd1b14043f3b");
    }
}

TEST_CASE("WebSeedClient::validate_torrent_file", "[db][snapshot][bittorrent]") {
    WebSeedClientForTest client{{kErigon2Snapshots}, {{"v1-010000-010500-bodies.seg", "542b3f77a2f3c4b9d8a4085d838bdd1b14043f3b"}}};
    CHECK(client.validate_torrent_file(make_e2_snapshots_provider_url(), "v1-010000-010500-bodies.seg.torrent", kValidTorrentContentAscii));

    CHECK_THROWS_AS(client.validate_torrent_file(make_e2_snapshots_provider_url(), "v1-010000-010500-bodies.seg.torrent", ""), boost::system::system_error);
    CHECK_THROWS_AS(client.validate_torrent_file(make_e2_snapshots_provider_url(), "v1-010000-010500-bodies.seg.torrent", "AA"), boost::system::system_error);
}

TEST_CASE("WebSeedClient::is_whitelisted", "[db][snapshot][bittorrent]") {
    static const Whitelist kWhitelist = {
        {"v1-010000-010500-bodies.seg", "542b3f77a2f3c4b9d8a4085d838bdd1b14043f3b"},
        {"v1-010000-010500-headers.seg", "080d0cd1613831820c8f5e48715d68643f48054a"},
        {"v1-010000-010500-transactions.seg", "8151bbc8b6635465760af6ebcfd630c9679b31a5"},
    };
    WebSeedClientForTest client{{kErigon2Snapshots}, kWhitelist};

    CHECK(client.is_whitelisted("v1-010000-010500-bodies.seg", "542b3f77a2f3c4b9d8a4085d838bdd1b14043f3b"));
    CHECK(client.is_whitelisted("v1-010000-010500-headers.seg", "080d0cd1613831820c8f5e48715d68643f48054a"));
    CHECK(client.is_whitelisted("v1-010000-010500-transactions.seg", "8151bbc8b6635465760af6ebcfd630c9679b31a5"));

    CHECK_FALSE(client.is_whitelisted("", ""));
    CHECK_FALSE(client.is_whitelisted("v1-010000-010500-bodies2.seg", "542b3f77a2f3c4b9d8a4085d838bdd1b14043f3b"));     // name
    CHECK_FALSE(client.is_whitelisted("v1-010000-010500-bodies.segment", "542b3f77a2f3c4b9d8a4085d838bdd1b14043f3b"));  // suffix
    CHECK_FALSE(client.is_whitelisted("v1-010000-010500-bodies.seg", "442b3f77a2f3c4b9d8a4085d838bdd1b14043f3b"));      // hash
}

}  // namespace silkworm::snapshots::bittorrent
