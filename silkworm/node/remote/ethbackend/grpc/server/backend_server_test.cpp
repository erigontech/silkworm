// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "backend_server.hpp"

#include <chrono>
#include <condition_variable>  // DO NOT remove: used for std::condition_variable, CLion suggestion is buggy
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <absl/strings/match.h>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/os.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/infra/grpc/common/util.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/interfaces/remote/kv.pb.h>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/node/backend/ethereum_backend.hpp>
#include <silkworm/node/remote/ethbackend/grpc/server/backend_calls.hpp>
#include <silkworm/sentry/api/common/sentry_client.hpp>

using namespace std::chrono_literals;

namespace {  // Trick to avoid name clashes in multiple test modules

class BackEndClient {
  public:
    explicit BackEndClient(remote::ETHBACKEND::StubInterface* stub) : stub_(stub) {}

    grpc::Status etherbase(remote::EtherbaseReply* response) {
        grpc::ClientContext context;
        return stub_->Etherbase(&context, remote::EtherbaseRequest{}, response);
    }

    grpc::Status net_version(remote::NetVersionReply* response) {
        grpc::ClientContext context;
        return stub_->NetVersion(&context, remote::NetVersionRequest{}, response);
    }

    grpc::Status net_peer_count(remote::NetPeerCountReply* response) {
        grpc::ClientContext context;
        return stub_->NetPeerCount(&context, remote::NetPeerCountRequest{}, response);
    }

    grpc::Status version(types::VersionReply* response) {
        grpc::ClientContext context;
        return stub_->Version(&context, google::protobuf::Empty{}, response);
    }

    grpc::Status protocol_version(remote::ProtocolVersionReply* response) {
        grpc::ClientContext context;
        return stub_->ProtocolVersion(&context, remote::ProtocolVersionRequest{}, response);
    }

    grpc::Status client_version(remote::ClientVersionReply* response) {
        grpc::ClientContext context;
        return stub_->ClientVersion(&context, remote::ClientVersionRequest{}, response);
    }

    grpc::Status subscribe_and_consume(const remote::SubscribeRequest& request,
                                       std::vector<remote::SubscribeReply>& responses) {
        grpc::ClientContext context;
        auto subscribe_reply_reader = stub_->Subscribe(&context, request);
        bool has_more{true};
        do {
            has_more = subscribe_reply_reader->Read(&responses.emplace_back());
        } while (has_more);
        responses.pop_back();
        return subscribe_reply_reader->Finish();
    }

    grpc::Status node_info(const remote::NodesInfoRequest& request, remote::NodesInfoReply* response) {
        grpc::ClientContext context;
        return stub_->NodeInfo(&context, request, response);
    }

  private:
    remote::ETHBACKEND::StubInterface* stub_;
};

constexpr uint64_t kTestSentryPeerCount = 10;
constexpr std::string_view kTestSentryNodeId{"24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d"};
constexpr std::string_view kTestSentryNodeClientId{"MockSentryClient"};

class MockSentryClient
    : public std::enable_shared_from_this<MockSentryClient>,
      public silkworm::sentry::api::SentryClient,
      public silkworm::sentry::api::Service {
    template <typename T>
    using Task = silkworm::Task<T>;

    Task<std::shared_ptr<silkworm::sentry::api::Service>> service() override {
        co_return shared_from_this();
    }
    bool is_ready() override { return true; }
    void on_disconnect(std::function<Task<void>()> /*callback*/) override {}
    Task<void> reconnect() override { co_return; }

    Task<void> set_status(silkworm::sentry::eth::StatusData /*status_data*/) override {
        throw std::runtime_error("not implemented");
    }
    Task<uint8_t> handshake() override {
        throw std::runtime_error("not implemented");
    }
    Task<NodeInfos> node_infos() override {
        const std::string ip_str = "1.2.3.4";
        const uint16_t port = 50555;
        const std::string node_url_str = std::string("enode://") + std::string{kTestSentryNodeId} + "@" + ip_str + ":" + std::to_string(port);

        silkworm::sentry::api::NodeInfo info = {
            silkworm::sentry::EnodeUrl{node_url_str},
            std::string{kTestSentryNodeClientId},
            boost::asio::ip::tcp::endpoint{boost::asio::ip::make_address(ip_str), port},
            port,
        };
        co_return NodeInfos{info};
    }

    Task<PeerKeys> send_message_by_id(silkworm::sentry::Message /*message*/, silkworm::sentry::EccPublicKey /*public_key*/) override {
        throw std::runtime_error("not implemented");
    }
    Task<PeerKeys> send_message_to_random_peers(silkworm::sentry::Message /*message*/, size_t /*max_peers*/) override {
        throw std::runtime_error("not implemented");
    }
    Task<PeerKeys> send_message_to_all(silkworm::sentry::Message /*message*/) override {
        throw std::runtime_error("not implemented");
    }
    Task<PeerKeys> send_message_by_min_block(silkworm::sentry::Message /*message*/, size_t /*max_peers*/) override {
        throw std::runtime_error("not implemented");
    }
    Task<void> peer_min_block(silkworm::sentry::EccPublicKey /*public_key*/) override {
        throw std::runtime_error("not implemented");
    }
    Task<void> messages(
        silkworm::sentry::api::MessageIdSet /*message_id_filter*/,
        std::function<Task<void>(silkworm::sentry::api::MessageFromPeer)> /*consumer*/) override {
        throw std::runtime_error("not implemented");
    }

    Task<silkworm::sentry::api::PeerInfos> peers() override {
        throw std::runtime_error("not implemented");
    }
    Task<size_t> peer_count() override {
        co_return kTestSentryPeerCount;
    }
    Task<std::optional<silkworm::sentry::api::PeerInfo>> peer_by_id(silkworm::sentry::EccPublicKey /*public_key*/) override {
        throw std::runtime_error("not implemented");
    }
    Task<void> penalize_peer(silkworm::sentry::EccPublicKey /*public_key*/) override {
        throw std::runtime_error("not implemented");
    }
    Task<void> peer_events(std::function<Task<void>(silkworm::sentry::api::PeerEvent)> /*consumer*/) override {
        throw std::runtime_error("not implemented");
    }
};

// TODO(canepat): better copy grpc_pick_unused_port_or_die to generate unused port
constexpr std::string_view kTestAddressUri{"localhost:12345"};

const silkworm::datastore::kvdb::MapConfig kTestMap{"TestTable"};
const silkworm::datastore::kvdb::MapConfig kTestMultiMap{"TestMultiTable", mdbx::key_mode::usual, mdbx::value_mode::multi};

using namespace silkworm;
using namespace silkworm::datastore::kvdb;

using StateChangeTokenObserver = std::function<void(std::optional<StateChangeToken>)>;

class TestableStateChangeCollection : public StateChangeCollection {
  public:
    std::optional<StateChangeToken> subscribe(StateChangeConsumer consumer, StateChangeFilter filter) override {
        const auto token = StateChangeCollection::subscribe(consumer, filter);
        if (token_observer_) {
            token_observer_(token);
        }
        return token;
    }

    void set_token(StateChangeToken next_token) { next_token_ = next_token; }

    void register_token_observer(StateChangeTokenObserver token_observer) { token_observer_ = std::move(token_observer); }

  private:
    StateChangeTokenObserver token_observer_;
};

class TestableEthereumBackEnd : public EthereumBackEnd {
  public:
    TestableEthereumBackEnd(const NodeSettings& node_settings, datastore::kvdb::ROAccess chaindata)
        : EthereumBackEnd{
              node_settings,
              std::move(chaindata),
              std::make_shared<MockSentryClient>(),
              std::make_unique<TestableStateChangeCollection>(),
          } {}

    TestableStateChangeCollection* state_change_source_for_test() const noexcept {
        return dynamic_cast<TestableStateChangeCollection*>(EthereumBackEnd::state_change_source());
    }
};

using BackEndServer = ethbackend::grpc::server::BackEndServer;

struct BackEndE2ETest {
    explicit BackEndE2ETest(
        const NodeSettings& options = {}) {
        std::shared_ptr<grpc::Channel> channel =
            grpc::CreateChannel(std::string{kTestAddressUri}, grpc::InsecureChannelCredentials());
        ethbackend_stub = remote::ETHBACKEND::NewStub(channel);
        backend_client = std::make_unique<BackEndClient>(ethbackend_stub.get());

        srv_config.context_pool_settings.num_contexts = 1;
        srv_config.address_uri = kTestAddressUri;

        DataDirectory data_dir{tmp_dir.path()};
        REQUIRE_NOTHROW(data_dir.deploy());
        db_config = std::make_unique<EnvConfig>();
        db_config->max_readers = options.chaindata_env_config.max_readers;
        db_config->path = data_dir.chaindata().path().string();
        db_config->create = true;
        db_config->in_memory = true;
        database_env = open_env(*db_config);
        auto rw_txn{database_env.start_write()};
        open_map(rw_txn, kTestMap);
        open_map(rw_txn, kTestMultiMap);
        rw_txn.commit();

        backend = std::make_unique<TestableEthereumBackEnd>(options, datastore::kvdb::ROAccess{database_env});
        server = std::make_unique<BackEndServer>(srv_config, *backend);
        server->build_and_start();
    }

    void fill_tables() {
        auto rw_txn = database_env.start_write();
        PooledCursor rw_cursor1{rw_txn, kTestMap};
        rw_cursor1.upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
        rw_cursor1.upsert(mdbx::slice{"BB"}, mdbx::slice{"11"});
        PooledCursor rw_cursor2{rw_txn, kTestMultiMap};
        rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
        rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"11"});
        rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"22"});
        rw_cursor2.upsert(mdbx::slice{"BB"}, mdbx::slice{"22"});
        rw_txn.commit();
    }

    void alter_tables() {
        auto rw_txn = database_env.start_write();
        PooledCursor rw_cursor1{rw_txn, kTestMap};
        rw_cursor1.upsert(mdbx::slice{"CC"}, mdbx::slice{"22"});
        PooledCursor rw_cursor2{rw_txn, kTestMultiMap};
        rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"33"});
        rw_cursor2.upsert(mdbx::slice{"BB"}, mdbx::slice{"33"});
        rw_txn.commit();
    }

    ~BackEndE2ETest() {
        server->shutdown();
        server->join();
    }

    std::unique_ptr<remote::ETHBACKEND::Stub> ethbackend_stub;
    std::unique_ptr<BackEndClient> backend_client;
    rpc::ServerSettings srv_config;
    TemporaryDirectory tmp_dir;
    std::unique_ptr<EnvConfig> db_config;
    mdbx::env_managed database_env;
    std::unique_ptr<TestableEthereumBackEnd> backend;
    std::unique_ptr<BackEndServer> server;
};

}  // namespace

namespace silkworm::ethbackend::grpc::server {

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE("BackEndServer", "[silkworm][node][rpc]") {
    log::init();
    rpc::ServerSettings srv_config;
    srv_config.address_uri = kTestAddressUri;
    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    REQUIRE_NOTHROW(data_dir.deploy());
    EnvConfig db_config{data_dir.chaindata().path().string()};
    db_config.create = true;
    db_config.in_memory = true;
    auto chaindata_env = open_env(db_config);
    NodeSettings node_settings;
    TestableEthereumBackEnd backend{node_settings, datastore::kvdb::ROAccess{chaindata_env}};

    SECTION("BackEndServer::BackEndServer OK: create/destroy server") {
        BackEndServer server{srv_config, backend};
    }

    SECTION("BackEndServer::BackEndServer OK: create/shutdown/destroy server") {
        BackEndServer server{srv_config, backend};
        server.shutdown();
    }

    SECTION("BackEndServer::build_and_start OK: run server in separate thread") {
        BackEndServer server{srv_config, backend};
        server.build_and_start();
        std::thread server_thread{[&server]() { server.join(); }};
        server.shutdown();
        server_thread.join();
    }

    SECTION("BackEndServer::build_and_start OK: create/shutdown/run/destroy server") {
        BackEndServer server{srv_config, backend};
        server.shutdown();
        server.build_and_start();
    }

    SECTION("BackEndServer::shutdown OK: shutdown server not running") {
        BackEndServer server{srv_config, backend};
        server.shutdown();
    }

    SECTION("BackEndServer::shutdown OK: shutdown twice server not running") {
        BackEndServer server{srv_config, backend};
        server.shutdown();
        server.shutdown();
    }

    SECTION("BackEndServer::shutdown OK: shutdown running server") {
        BackEndServer server{srv_config, backend};
        server.build_and_start();
        server.shutdown();
        server.join();
    }

    SECTION("BackEndServer::shutdown OK: shutdown twice running server") {
        BackEndServer server{srv_config, backend};
        server.build_and_start();
        server.shutdown();
        server.shutdown();
        server.join();
    }

    SECTION("BackEndServer::shutdown OK: shutdown running server again after join") {
        BackEndServer server{srv_config, backend};
        server.build_and_start();
        server.shutdown();
        server.join();
        server.shutdown();
    }

    SECTION("BackEndServer::join OK: shutdown joined server") {
        BackEndServer server{srv_config, backend};
        server.build_and_start();
        std::thread server_thread{[&server]() { server.join(); }};
        server.shutdown();
        server_thread.join();
    }

    SECTION("BackEndServer::join OK: shutdown joined server and join again") {
        BackEndServer server{srv_config, backend};
        server.build_and_start();
        std::thread server_thread{[&server]() { server.join(); }};
        server.shutdown();
        server_thread.join();
        server.join();  // cannot move before server_thread.join() due to data race in boost::asio::detail::posix_thread
    }
}

TEST_CASE("BackEndServer E2E: empty node settings", "[silkworm][node][rpc]") {
    log::init();
    BackEndE2ETest test;
    auto backend_client = *test.backend_client;

    SECTION("Etherbase: return missing coinbase error") {
        remote::EtherbaseReply response;
        const auto status = backend_client.etherbase(&response);
        CHECK(!status.ok());
        CHECK(status.error_code() == ::grpc::StatusCode::INTERNAL);
        CHECK(status.error_message() == "etherbase must be explicitly specified");
        CHECK(!response.has_address());
    }

    SECTION("NetVersion: return out-of-range network ID") {
        remote::NetVersionReply response;
        const auto status = backend_client.net_version(&response);
        CHECK(status.ok());
        CHECK(response.id() == 0);
    }

    SECTION("Version: return ETHBACKEND version") {
        types::VersionReply response;
        const auto status = backend_client.version(&response);
        CHECK(status.ok());
        CHECK(response.major() == 2);
        CHECK(response.minor() == 3);
        CHECK(response.patch() == 0);
    }

    SECTION("ProtocolVersion: return ETH protocol version") {
        remote::ProtocolVersionReply response;
        const auto status = backend_client.protocol_version(&response);
        CHECK(status.ok());
        CHECK(response.id() == kEthDevp2pProtocolVersion);
    }

    SECTION("ClientVersion: return Silkworm client version") {
        remote::ClientVersionReply response;
        const auto status = backend_client.client_version(&response);
        CHECK(status.ok());
        CHECK(absl::StrContains(response.node_name(), "silkworm"));
    }

    // TODO(canepat): change using something meaningful when really implemented
    SECTION("Subscribe: return streamed subscriptions") {
        remote::SubscribeRequest request;
        std::vector<remote::SubscribeReply> responses;
        const auto status = backend_client.subscribe_and_consume(request, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 2);
    }
}

TEST_CASE("BackEndServer E2E: mainnet chain with zero etherbase", "[silkworm][node][rpc]") {
    log::init();
    NodeSettings node_settings;
    node_settings.chain_config = kMainnetConfig;
    node_settings.etherbase = evmc::address{};
    BackEndE2ETest test{node_settings};
    auto backend_client = *test.backend_client;

    SECTION("Etherbase: return coinbase address") {
        remote::EtherbaseReply response;
        const auto status = backend_client.etherbase(&response);
        CHECK(status.ok());
        CHECK(response.has_address());
        CHECK(response.address() == types::H160());
    }

    SECTION("NetVersion: return network ID") {
        remote::NetVersionReply response;
        const auto status = backend_client.net_version(&response);
        CHECK(status.ok());
        CHECK(response.id() == kMainnetConfig.chain_id);
    }
}

TEST_CASE("BackEndServer E2E: one Sentry status OK", "[silkworm][node][rpc]") {
    BackEndE2ETest test;
    auto backend_client = *test.backend_client;

    SECTION("NetPeerCount: return peer count") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status.ok());
        CHECK(response.count() == kTestSentryPeerCount);
    }

    SECTION("NodeInfo: return information about nodes") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status.ok());
        CHECK(response.nodes_info_size() == 1);
        CHECK(response.nodes_info(0).id() == kTestSentryNodeId);
        CHECK(response.nodes_info(0).name() == kTestSentryNodeClientId);
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::ethbackend::grpc::server
