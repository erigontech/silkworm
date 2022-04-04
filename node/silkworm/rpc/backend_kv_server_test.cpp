/*
   Copyright 2022 The Silkworm Authors

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

#include "backend_kv_server.hpp"

#include <memory>
#include <string>
#include <sstream>
#include <thread>
#include <vector>

#include <catch2/catch.hpp>
#include <grpc/grpc.h>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/rpc/util.hpp>
#include <types/types.pb.h>

namespace { // Trick suggested by gRPC team to avoid name clashes in multiple test modules
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

    grpc::Status subscribe_and_consume(const remote::SubscribeRequest& request, std::vector<remote::SubscribeReply>& responses) {
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

class KvClient {
  public:
    explicit KvClient(remote::KV::StubInterface* stub) : stub_(stub) {}

    grpc::Status version(types::VersionReply* response) {
        grpc::ClientContext context;
        return stub_->Version(&context, google::protobuf::Empty{}, response);
    }

    grpc::Status tx(std::vector<remote::Cursor>& requests, std::vector<remote::Pair>& responses) {
        grpc::ClientContext context;
        auto tx_reader_writer = stub_->Tx(&context);
        tx_reader_writer->Read(&responses.emplace_back());
        uint32_t cursor_id{0};
        for (auto& req : requests) {
            req.set_cursor(cursor_id);
            const bool write_ok = tx_reader_writer->Write(req);
            if (!write_ok) {
                break;
            }
            const bool read_ok = tx_reader_writer->Read(&responses.emplace_back());
            if (!read_ok) {
                responses.pop_back();
                break;
            }
            if (cursor_id == 0) {
                cursor_id = responses.back().cursorid();
            }
        }
        tx_reader_writer->WritesDone();
        return tx_reader_writer->Finish();
    }

    grpc::Status statechanges_and_consume(const remote::StateChangeRequest& request, std::vector<remote::StateChangeBatch>& responses) {
        grpc::ClientContext context;
        auto subscribe_reply_reader = stub_->StateChanges(&context, request);
        bool has_more{true};
        do {
            has_more = subscribe_reply_reader->Read(&responses.emplace_back());
        } while (has_more);
        responses.pop_back();
        return subscribe_reply_reader->Finish();
    }

  private:
    remote::KV::StubInterface* stub_;
};

const uint64_t kTestSentryPeerCount{10};
constexpr const char* kTestSentryPeerId{"peer_id"};
constexpr const char* kTestSentryPeerName{"peer_name"};

class SentryService : public sentry::Sentry::Service {
  public:
    explicit SentryService(grpc::Status status) : status_(status) {}

    std::unique_ptr<grpc::Server> build_and_start(const std::string& server_address) {
        grpc::ServerBuilder builder;
        builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
        builder.RegisterService(this);
        return builder.BuildAndStart();
    }

    grpc::Status PeerCount(::grpc::ServerContext* /*context*/, const ::sentry::PeerCountRequest* /*request*/, ::sentry::PeerCountReply* response) override {
        if (status_.ok()) {
            response->set_count(kTestSentryPeerCount);
        }
        return status_;
    }

    grpc::Status NodeInfo(::grpc::ServerContext* /*context*/, const ::google::protobuf::Empty* /*request*/, ::types::NodeInfoReply* response) override {
        response->set_id(kTestSentryPeerId);
        response->set_name(kTestSentryPeerName);
        return status_;
    }

  private:
    grpc::Status status_;
};

// TODO(canepat): better copy grpc_pick_unused_port_or_die to generate unused port
static const std::string kTestAddressUri{"localhost:12345"};

static const std::string kTestSentryAddress1{"localhost:54321"};
static const std::string kTestSentryAddress2{"localhost:54322"};

using namespace silkworm;

struct BackEndKvE2eTest {
    BackEndKvE2eTest(silkworm::log::Level log_verbosity, const NodeSettings& options = {}, std::vector<grpc::Status> statuses = {})
        : node_settings(options) {
        silkworm::log::set_verbosity(log_verbosity);
        std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(kTestAddressUri, grpc::InsecureChannelCredentials());
        ethbackend_stub = remote::ETHBACKEND::NewStub(channel);
        backend_client = std::make_unique<BackEndClient>(ethbackend_stub.get());
        kv_stub = remote::KV::NewStub(channel);
        kv_client = std::make_unique<KvClient>(kv_stub.get());

        srv_config.set_num_contexts(1);
        srv_config.set_address_uri(kTestAddressUri);

        DataDirectory data_dir{tmp_dir.path()};
        REQUIRE_NOTHROW(data_dir.deploy());
        db_config = std::make_unique<db::EnvConfig>();
        db_config->path = data_dir.chaindata().path().string();
        db_config->create = true;
        db_config->inmemory = true;
        database_env = db::open_env(*db_config);
        auto rw_txn{database_env.start_write()};
        db::open_map(rw_txn, test_map_config);
        rw_txn.commit();

        backend = std::make_unique<EthereumBackEnd>(node_settings, &database_env);
        server = std::make_unique<rpc::BackEndKvServer>(srv_config, *backend);
        server->build_and_start();

        std::stringstream sentry_list_stream{node_settings.sentry_api_addr};
        std::string sentry_address;
        std::size_t i{0};
        while (std::getline(sentry_list_stream, sentry_address, kSentryAddressDelimiter)) {
            SILKWORM_ASSERT(i < statuses.size());
            sentry_services.emplace_back(std::make_unique<SentryService>(statuses[i]));
            sentry_servers.emplace_back(sentry_services.back()->build_and_start(sentry_address));
            ++i;
        }
    }

    void fill_test_table() {
        auto rw_txn = database_env.start_write();
        db::Cursor rw_cursor{rw_txn, test_map_config};
        rw_cursor.upsert(mdbx::slice{"00"}, mdbx::slice{"11"});
        rw_txn.commit();
    }

    ~BackEndKvE2eTest() {
        server->shutdown();
        server->join();
        for (auto& sentry_server : sentry_servers) {
            sentry_server->Shutdown();
            sentry_server->Wait();
        }
    }

    rpc::Grpc2SilkwormLogGuard log_guard;
    std::unique_ptr<remote::ETHBACKEND::Stub> ethbackend_stub;
    std::unique_ptr<BackEndClient> backend_client;
    std::unique_ptr<remote::KV::Stub> kv_stub;
    std::unique_ptr<KvClient> kv_client;
    rpc::ServerConfig srv_config;
    TemporaryDirectory tmp_dir;
    std::unique_ptr<db::EnvConfig> db_config;
    mdbx::env_managed database_env;
    const db::MapConfig test_map_config{"TestTable"};
    const NodeSettings& node_settings;
    std::unique_ptr<EthereumBackEnd> backend;
    std::unique_ptr<rpc::BackEndKvServer> server;
    std::vector<std::unique_ptr<SentryService>> sentry_services;
    std::vector<std::unique_ptr<grpc::Server>> sentry_servers;
};
} // namespace anonymous

namespace silkworm::rpc {

TEST_CASE("BackEndKvServer", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    Grpc2SilkwormLogGuard log_guard;
    ServerConfig srv_config;
    srv_config.set_address_uri(kTestAddressUri);
    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    REQUIRE_NOTHROW(data_dir.deploy());
    db::EnvConfig db_config{data_dir.chaindata().path().string()};
    db_config.create = true;
    db_config.inmemory = true;
    auto database_env = db::open_env(db_config);
    NodeSettings node_settings;
    EthereumBackEnd backend{node_settings, &database_env};

    SECTION("BackEndKvServer::BackEndKvServer OK: create/destroy server", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
    }

    SECTION("BackEndKvServer::BackEndKvServer OK: create/shutdown/destroy server", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.shutdown();
    }

    SECTION("BackEndKvServer::build_and_start OK: run server in separate thread", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        std::thread server_thread{[&server]() {
            server.join();
        }};
        server.shutdown();
        server_thread.join();
    }

    SECTION("BackEndKvServer::build_and_start OK: create/shutdown/run/destroy server", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.shutdown();
        server.build_and_start();
    }

    SECTION("BackEndKvServer::shutdown OK: shutdown server not running", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.shutdown();
    }

    SECTION("BackEndKvServer::shutdown OK: shutdown twice server not running", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.shutdown();
        server.shutdown();
    }

    SECTION("BackEndKvServer::shutdown OK: shutdown running server", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        server.shutdown();
        server.join();
    }

    SECTION("BackEndKvServer::shutdown OK: shutdown twice running server", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        server.shutdown();
        server.shutdown();
        server.join();
    }

    SECTION("BackEndKvServer::shutdown OK: shutdown running server again after join", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        server.shutdown();
        server.join();
        server.shutdown();
    }

    SECTION("BackEndKvServer::join OK: shutdown joined server", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        std::thread server_thread{[&server]() {
            server.join();
        }};
        server.shutdown();
        server_thread.join();
    }

    SECTION("BackEndKvServer::join OK: shutdown joined server and join again", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        std::thread server_thread{[&server]() {
            server.join();
        }};
        server.shutdown();
        server_thread.join();
        server.join(); // cannot move before server_thread.join() due to data race in boost::asio::detail::posix_thread
    }
}

TEST_CASE("BackEndKvServer E2E: empty node settings", "[silkworm][node][rpc]") {
    BackEndKvE2eTest test{silkworm::log::Level::kNone};
    auto backend_client = *test.backend_client;
    auto kv_client = *test.kv_client;

    SECTION("Etherbase: return missing coinbase error", "[silkworm][node][rpc]") {
        remote::EtherbaseReply response;
        const auto status = backend_client.etherbase(&response);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INTERNAL);
        CHECK(status.error_message() == "etherbase must be explicitly specified");
        CHECK(!response.has_address());
    }

    SECTION("NetVersion: return out-of-range network ID", "[silkworm][node][rpc]") {
        remote::NetVersionReply response;
        const auto status = backend_client.net_version(&response);
        CHECK(status.ok());
        CHECK(response.id() == 0);
    }

    SECTION("NetPeerCount: return zero peer count", "[silkworm][node][rpc]") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status.ok());
        CHECK(response.count() == 0);
    }

    SECTION("Version: return ETHBACKEND version", "[silkworm][node][rpc]") {
        types::VersionReply response;
        const auto status = backend_client.version(&response);
        CHECK(status.ok());
        CHECK(response.major() == 2);
        CHECK(response.minor() == 2);
        CHECK(response.patch() == 0);
    }

    SECTION("ProtocolVersion: return ETH protocol version", "[silkworm][node][rpc]") {
        remote::ProtocolVersionReply response;
        const auto status = backend_client.protocol_version(&response);
        CHECK(status.ok());
        CHECK(response.id() == kEthDevp2pProtocolVersion);
    }

    SECTION("ClientVersion: return Silkworm client version", "[silkworm][node][rpc]") {
        remote::ClientVersionReply response;
        const auto status = backend_client.client_version(&response);
        CHECK(status.ok());
        CHECK(response.nodename().find("silkworm") != std::string::npos);
    }

    // TODO(canepat): change using something meaningful when really implemented
    SECTION("Subscribe: return streamed subscriptions", "[silkworm][node][rpc]") {
        remote::SubscribeRequest request;
        std::vector<remote::SubscribeReply> responses;
        const auto status = backend_client.subscribe_and_consume(request, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 2);
    }

    SECTION("NodeInfo: return information about zero nodes", "[silkworm][node][rpc]") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status.ok());
        CHECK(response.nodesinfo_size() == 0);
    }

    SECTION("Version: return KV version", "[silkworm][node][rpc]") {
        types::VersionReply response;
        const auto status = kv_client.version(&response);
        CHECK(status.ok());
        CHECK(response.major() == 5);
        CHECK(response.minor() == 1);
        CHECK(response.patch() == 0);
    }

    SECTION("Tx KO: empty table name", "[silkworm][node][rpc]") {
        remote::SubscribeRequest request;
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        std::vector<remote::Cursor> requests{open};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
        CHECK(status.error_message().find("unknown bucket") != std::string::npos);
        CHECK(responses.size() == 1);
        CHECK(responses[0].txid() != 0);
    }

    SECTION("Tx KO: invalid table name", "[silkworm][node][rpc]") {
        remote::SubscribeRequest request;
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname("UnexistentTable");
        std::vector<remote::Cursor> requests{open};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
        CHECK(status.error_message().find("unknown bucket") != std::string::npos);
        CHECK(responses.size() == 1);
        CHECK(responses[0].txid() != 0);
    }

    SECTION("Tx KO: missing operation", "[silkworm][node][rpc]") {
        remote::SubscribeRequest request;
        remote::Cursor open;
        open.set_bucketname("TestTable");
        std::vector<remote::Cursor> requests{open};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
        CHECK(status.error_message().find("unknown cursor") != std::string::npos);
        CHECK(responses.size() == 1);
        CHECK(responses[0].txid() != 0);
    }

    SECTION("Tx OK: cursor opened", "[silkworm][node][rpc]") {
        remote::SubscribeRequest request;
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname("TestTable");
        std::vector<remote::Cursor> requests{open};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 2);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
    }

    SECTION("Tx OK: cursor opened then closed", "[silkworm][node][rpc]") {
        remote::SubscribeRequest request;
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname("TestTable");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        std::vector<remote::Cursor> requests{open, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 3);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].cursorid() == 0);
    }

    SECTION("Tx KO: cursor first in empty table", "[silkworm][node][rpc]") {
        remote::SubscribeRequest request;
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname("TestTable");
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        std::vector<remote::Cursor> requests{open, first};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(responses.size() == 2);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
    }

    SECTION("Tx KO: cursor next in empty table", "[silkworm][node][rpc]") {
        remote::SubscribeRequest request;
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname("TestTable");
        remote::Cursor next;
        next.set_op(remote::Op::NEXT);
        std::vector<remote::Cursor> requests{open, next};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(responses.size() == 2);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
    }

    SECTION("Tx cursor first: OK", "[silkworm][node][rpc]") {
        test.fill_test_table();

        remote::SubscribeRequest request;
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname("TestTable");
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        std::vector<remote::Cursor> requests{open, first, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(status.error_message().empty());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "00");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].cursorid() == 0);
    }

    // TODO(canepat): change using something meaningful when really implemented
    SECTION("StateChanges: return streamed state changes", "[silkworm][node][rpc]") {
        remote::StateChangeRequest request;
        std::vector<remote::StateChangeBatch> responses;
        const auto status = kv_client.statechanges_and_consume(request, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 2);
    }
}

TEST_CASE("BackEndKvServer E2E: mainnet chain, etherbase set", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.chain_config = *silkworm::lookup_chain_config("mainnet");
    node_settings.etherbase = evmc::address{};
    BackEndKvE2eTest test{silkworm::log::Level::kNone, node_settings};
    auto backend_client = *test.backend_client;

    SECTION("Etherbase: return coinbase address", "[silkworm][node][rpc]") {
        remote::EtherbaseReply response;
        const auto status = backend_client.etherbase(&response);
        CHECK(status.ok());
        CHECK(response.has_address());
        CHECK(response.address() == types::H160());
    }

    SECTION("NetVersion: return network ID", "[silkworm][node][rpc]") {
        remote::NetVersionReply response;
        const auto status = backend_client.net_version(&response);
        CHECK(status.ok());
        CHECK(response.id() == kMainnetConfig.chain_id);
    }
}

TEST_CASE("BackEndKvServer E2E: one Sentry, status OK", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.sentry_api_addr = kTestSentryAddress1;
    BackEndKvE2eTest test{silkworm::log::Level::kNone, node_settings, {grpc::Status::OK}};
    auto backend_client = *test.backend_client;

    SECTION("NetPeerCount: return peer count", "[silkworm][node][rpc]") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status.ok());
        CHECK(response.count() == kTestSentryPeerCount);
    }

    SECTION("NodeInfo: return information about nodes", "[silkworm][node][rpc]") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status.ok());
        CHECK(response.nodesinfo_size() == 1);
        CHECK(response.nodesinfo(0).id() == kTestSentryPeerId);
        CHECK(response.nodesinfo(0).name() == kTestSentryPeerName);
    }
}

TEST_CASE("BackEndKvServer E2E: one Sentry, status KO", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.sentry_api_addr = kTestSentryAddress1;
    grpc::Status DEADLINE_EXCEEDED_ERROR{grpc::StatusCode::DEADLINE_EXCEEDED, "timeout"};
    BackEndKvE2eTest test{silkworm::log::Level::kNone, node_settings, {DEADLINE_EXCEEDED_ERROR}};
    auto backend_client = *test.backend_client;

    SECTION("NetPeerCount: return expected status error", "[silkworm][node][rpc]") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status == DEADLINE_EXCEEDED_ERROR);
    }

    SECTION("NodeInfo: return expected status error", "[silkworm][node][rpc]") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status == DEADLINE_EXCEEDED_ERROR);
    }
}

TEST_CASE("BackEndKvServer E2E: more than one Sentry, all status OK", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.sentry_api_addr = kTestSentryAddress1 + "," + kTestSentryAddress2;
    BackEndKvE2eTest test{silkworm::log::Level::kNone, node_settings, {grpc::Status::OK, grpc::Status::OK}};
    auto backend_client = *test.backend_client;

    SECTION("NetPeerCount: return peer count", "[silkworm][node][rpc]") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status.ok());
        CHECK(response.count() == 2 * kTestSentryPeerCount);
    }

    SECTION("NodeInfo: return information about nodes", "[silkworm][node][rpc]") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status.ok());
        CHECK(response.nodesinfo_size() == 2);
        for (int i{0}; i<response.nodesinfo_size(); i++) {
            const types::NodeInfoReply& nodes_info = response.nodesinfo(i);
            CHECK(nodes_info.id() == kTestSentryPeerId);
            CHECK(nodes_info.name() == kTestSentryPeerName);
        }
    }
}

TEST_CASE("BackEndKvServer E2E: more than one Sentry, at least one status KO", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.sentry_api_addr = kTestSentryAddress1 + "," + kTestSentryAddress2;
    BackEndKvE2eTest test{silkworm::log::Level::kNone, node_settings, {grpc::Status::OK, grpc::Status::CANCELLED}};
    auto backend_client = *test.backend_client;

    SECTION("NetPeerCount: return expected status error", "[silkworm][node][rpc]") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status == grpc::Status::CANCELLED);
    }

    SECTION("NodeInfo: return expected status error", "[silkworm][node][rpc]") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status == grpc::Status::CANCELLED);
    }
}

TEST_CASE("BackEndKvServer E2E: more than one Sentry, all status KO", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.sentry_api_addr = kTestSentryAddress1 + "," + kTestSentryAddress2;
    grpc::Status INTERNAL_ERROR{grpc::StatusCode::INTERNAL, "internal error"};
    grpc::Status DEADLINE_EXCEEDED_ERROR{grpc::StatusCode::DEADLINE_EXCEEDED, "timeout"};
    BackEndKvE2eTest test{silkworm::log::Level::kNone, node_settings, {INTERNAL_ERROR, DEADLINE_EXCEEDED_ERROR}};
    auto backend_client = *test.backend_client;

    SECTION("NetPeerCount: return expected status error", "[silkworm][node][rpc]") {
        remote::NetPeerCountReply response;
        /*const auto status =*/ backend_client.net_peer_count(&response);
        //CHECK((status == INTERNAL_ERROR || status == DEADLINE_EXCEEDED_ERROR));
    }

    /*SECTION("NodeInfo: return expected status error", "[silkworm][node][rpc]") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK((status == INTERNAL_ERROR || status == DEADLINE_EXCEEDED_ERROR));
    }*/
}

} // namespace silkworm::rpc
