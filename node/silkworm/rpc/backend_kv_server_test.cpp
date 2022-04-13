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

#include <chrono>
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

using TxStreamPtr = std::unique_ptr<grpc::ClientReaderWriterInterface<remote::Cursor, remote::Pair>>;

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
            if (req.cursor() == 0) {
                req.set_cursor(cursor_id);
            }
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
            if (req.op() == remote::Op::CLOSE) {
                cursor_id = 0;
            }
        }
        tx_reader_writer->WritesDone();
        return tx_reader_writer->Finish();
    }

    auto tx_start(grpc::ClientContext* context) {
        return stub_->Tx(context);
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

class SentryServer {
  public:
    explicit SentryServer(grpc::Status status) : status_(status) {}

    void build_and_start(const std::string& server_address) {
        grpc::ServerBuilder builder;
        builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
        builder.RegisterService(&service_);
        cq_ = builder.AddCompletionQueue();
        server_ = builder.BuildAndStart();
        server_thread_ = std::thread{[&]() { run(); }};
    }

    void stop() {
        server_->Shutdown();
        server_->Wait();
        cq_->Shutdown();
        void* tag{nullptr};
        bool ok{false};
        while (cq_->Next(&tag, &ok)) {
        }
        server_thread_.join();
    }

  private:
    void run() {
        grpc::ServerContext pc_context;
        sentry::PeerCountRequest pc_request;
        grpc::ServerAsyncResponseWriter<sentry::PeerCountReply> pc_responder{&pc_context};
        service_.RequestPeerCount(&pc_context, &pc_request, &pc_responder, cq_.get(), cq_.get(), PEER_COUNT_REQUEST_TAG);
        grpc::ServerContext ni_context;
        google::protobuf::Empty ni_request;
        grpc::ServerAsyncResponseWriter<types::NodeInfoReply> ni_responder{&ni_context};
        service_.RequestNodeInfo(&ni_context, &ni_request, &ni_responder, cq_.get(), cq_.get(), NODE_INFO_REQUEST_TAG);
        bool has_work{true};
        while (has_work) {
            void* tag{nullptr};
            bool ok{false};
            const bool got_event = cq_->Next(&tag, &ok);
            if (!got_event) {
                has_work = false;
                continue;
            }
            if (ok && tag == PEER_COUNT_REQUEST_TAG) {
                if (status_.ok()) {
                    sentry::PeerCountReply pc_reply;
                    if (status_.ok()) {
                        pc_reply.set_count(kTestSentryPeerCount);
                    }
                    pc_responder.Finish(pc_reply, status_, PEER_COUNT_FINISH_TAG);
                } else {
                    pc_responder.FinishWithError(status_, PEER_COUNT_FINISH_TAG);
                }
            }
            if (ok && tag == PEER_COUNT_FINISH_TAG) {
                continue;
            }
            if (ok && tag == NODE_INFO_REQUEST_TAG) {
                if (status_.ok()) {
                    types::NodeInfoReply ni_reply;
                    ni_reply.set_id(kTestSentryPeerId);
                    ni_reply.set_name(kTestSentryPeerName);
                    ni_responder.Finish(ni_reply, status_, NODE_INFO_FINISH_TAG);
                } else {
                    ni_responder.FinishWithError(status_, NODE_INFO_FINISH_TAG);
                }
            }
            if (ok && tag == NODE_INFO_FINISH_TAG) {
                continue;
            }
        }
    }

    inline static void* PEER_COUNT_REQUEST_TAG = reinterpret_cast<void*>(1);
    inline static void* PEER_COUNT_FINISH_TAG = reinterpret_cast<void*>(2);

    inline static void* NODE_INFO_REQUEST_TAG = reinterpret_cast<void*>(3);
    inline static void* NODE_INFO_FINISH_TAG = reinterpret_cast<void*>(4);

    grpc::Status status_;
    sentry::Sentry::AsyncService service_;
    std::unique_ptr<grpc::ServerCompletionQueue> cq_;
    std::unique_ptr<grpc::Server> server_;
    std::thread server_thread_;
};

// TODO(canepat): better copy grpc_pick_unused_port_or_die to generate unused port
static const std::string kTestAddressUri{"localhost:12345"};

static const std::string kTestSentryAddress1{"localhost:54321"};
static const std::string kTestSentryAddress2{"localhost:54322"};

static const silkworm::db::MapConfig kTestMap{"TestTable"};
static const silkworm::db::MapConfig kTestMultiMap{"TestMultiTable", mdbx::key_mode::usual, mdbx::value_mode::multi};

using namespace silkworm;

struct BackEndKvE2eTest {
    BackEndKvE2eTest(silkworm::log::Level log_verbosity, const NodeSettings& options = {}, std::vector<grpc::Status> statuses = {}) {
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
        db_config->max_readers = options.chaindata_env_config.max_readers;
        db_config->path = data_dir.chaindata().path().string();
        db_config->create = true;
        db_config->inmemory = true;
        database_env = db::open_env(*db_config);
        auto rw_txn{database_env.start_write()};
        db::open_map(rw_txn, kTestMap);
        rw_txn.commit();

        backend = std::make_unique<EthereumBackEnd>(options, &database_env);
        server = std::make_unique<rpc::BackEndKvServer>(srv_config, *backend);
        server->build_and_start();

        std::stringstream sentry_list_stream{options.sentry_api_addr};
        std::string sentry_address;
        std::size_t i{0};
        while (std::getline(sentry_list_stream, sentry_address, kSentryAddressDelimiter)) {
            SILKWORM_ASSERT(i < statuses.size());
            sentry_servers.emplace_back(std::make_unique<SentryServer>(statuses[i]));
            sentry_servers.back()->build_and_start(sentry_address);
            ++i;
        }
    }

    void fill_tables() {
        auto rw_txn = database_env.start_write();
        db::Cursor rw_cursor1{rw_txn, kTestMap};
        rw_cursor1.upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
        rw_cursor1.upsert(mdbx::slice{"BB"}, mdbx::slice{"11"});
        db::Cursor rw_cursor2{rw_txn, kTestMultiMap};
        rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
        rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"11"});
        rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"22"});
        rw_cursor2.upsert(mdbx::slice{"BB"}, mdbx::slice{"22"});
        rw_txn.commit();
    }

    ~BackEndKvE2eTest() {
        server->shutdown();
        server->join();
        for (auto& sentry_server : sentry_servers) {
            sentry_server->stop();
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
    std::unique_ptr<EthereumBackEnd> backend;
    std::unique_ptr<rpc::BackEndKvServer> server;
    std::vector<std::unique_ptr<SentryServer>> sentry_servers;
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
        remote::Cursor open;
        open.set_bucketname(kTestMap.name);
        std::vector<remote::Cursor> requests{open};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
        CHECK(status.error_message().find("unknown cursor") != std::string::npos);
        CHECK(responses.size() == 1);
        CHECK(responses[0].txid() != 0);
    }

    SECTION("Tx OK: just start then finish", "[silkworm][node][rpc]") {
        std::vector<remote::Cursor> requests{};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 1);
        CHECK(responses[0].txid() != 0);
    }

    SECTION("Tx OK: cursor opened", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        std::vector<remote::Cursor> requests{open};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 2);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
    }

    SECTION("Tx OK: cursor opened then closed", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);
        std::vector<remote::Cursor> requests{open, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 3);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].cursorid() == 0);
    }

    SECTION("Tx KO: cursor opened then unknown", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(12345);
        std::vector<remote::Cursor> requests{open, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
        CHECK(status.error_message().find("unknown cursor") != std::string::npos);
        CHECK(responses.size() == 2);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
    }

    SECTION("Tx OK: one FIRST operation on empty table gives empty result", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0);
        std::vector<remote::Cursor> requests{open, first};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 3);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[1].k().empty());
        CHECK(responses[1].v().empty());
    }

    SECTION("Tx KO: one NEXT operation on empty table gives empty result", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor next;
        next.set_op(remote::Op::NEXT);
        next.set_cursor(0);
        std::vector<remote::Cursor> requests{open, next};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 3);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[1].k().empty());
        CHECK(responses[1].v().empty());
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

TEST_CASE("BackEndKvServer E2E: mainnet chain with zero etherbase", "[silkworm][node][rpc]") {
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

TEST_CASE("BackEndKvServer E2E: one Sentry status OK", "[silkworm][node][rpc]") {
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

TEST_CASE("BackEndKvServer E2E: one Sentry status KO", "[silkworm][node][rpc]") {
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

TEST_CASE("BackEndKvServer E2E: more than one Sentry all status OK", "[silkworm][node][rpc]") {
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

TEST_CASE("BackEndKvServer E2E: more than one Sentry at least one status KO", "[silkworm][node][rpc]") {
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

TEST_CASE("BackEndKvServer E2E: more than one Sentry all status KO", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.sentry_api_addr = kTestSentryAddress1 + "," + kTestSentryAddress2;
    grpc::Status INTERNAL_ERROR{grpc::StatusCode::INTERNAL, "internal error"};
    grpc::Status INVALID_ARGUMENT_ERROR{grpc::StatusCode::INVALID_ARGUMENT, "invalid"};
    BackEndKvE2eTest test{silkworm::log::Level::kNone, node_settings, {INTERNAL_ERROR, INVALID_ARGUMENT_ERROR}};
    auto backend_client = *test.backend_client;

    SECTION("NetPeerCount: return expected status error", "[silkworm][node][rpc]") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK((status == INTERNAL_ERROR || status == INVALID_ARGUMENT_ERROR));
    }

    SECTION("NodeInfo: return expected status error", "[silkworm][node][rpc]") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK((status == INTERNAL_ERROR || status == INVALID_ARGUMENT_ERROR));
    }
}

TEST_CASE("BackEndKvServer E2E: trigger server-side write error", "[silkworm][node][rpc]") {
    {
        const uint32_t kNumTxs{1000};
        NodeSettings node_settings;
        BackEndKvE2eTest test{silkworm::log::Level::kError, node_settings};
        test.fill_tables();
        auto kv_client = *test.kv_client;

        // Start many Tx calls w/o reading responses after writing requests.
        for (uint32_t i{0}; i<kNumTxs; i++) {
            grpc::ClientContext context;
            auto tx_stream = kv_client.tx_start(&context);
            remote::Pair response;
            CHECK(tx_stream->Read(&response));
            CHECK(response.txid() != 0);
            remote::Cursor open;
            open.set_op(remote::Op::OPEN);
            open.set_bucketname(kTestMap.name);
            CHECK(tx_stream->Write(open));
        }
    }
    // Server-side lifecyle of Tx calls must be OK.
}

TEST_CASE("BackEndKvServer E2E: exceed max simultaneous readers", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    BackEndKvE2eTest test{silkworm::log::Level::kNone, node_settings};
    test.fill_tables();
    auto kv_client = *test.kv_client;

    // Start and keep open as many Tx calls as the maximum number of readers.
    std::vector<std::unique_ptr<grpc::ClientContext>> client_contexts;
    std::vector<TxStreamPtr> tx_streams;
    for (uint32_t i{0}; i<test.database_env.get_info().mi_maxreaders; i++) {
        auto& context = client_contexts.emplace_back(std::make_unique<grpc::ClientContext>());
        auto tx_stream = kv_client.tx_start(context.get());
        // You must read at least the first unsolicited incoming message (TxID announcement).
        remote::Pair response;
        CHECK(tx_stream->Read(&response));
        CHECK(response.txid() != 0);
        tx_streams.push_back(std::move(tx_stream));
    }

    // Now trying to start another Tx call will exceed the maximum number of readers.
    grpc::ClientContext context;
    const auto failing_tx_stream = kv_client.tx_start(&context);
    auto status2 = failing_tx_stream->Finish();
    CHECK(!status2.ok());
    CHECK(status2.error_code() == grpc::StatusCode::RESOURCE_EXHAUSTED);
    CHECK(status2.error_message().find("start tx failed") != std::string::npos);

    // Dispose all the opened Tx calls.
    for (const auto& tx_stream : tx_streams) {
        CHECK(tx_stream->WritesDone());
        auto status = tx_stream->Finish();
        CHECK(status.ok());
    }
}

class TxIdleTimeoutGuard {
  public:
    explicit TxIdleTimeoutGuard(uint8_t t) {
        TxCall::set_max_idle_duration(boost::posix_time::milliseconds{t});
    }
    ~TxIdleTimeoutGuard() {
        TxCall::set_max_idle_duration(kMaxIdleDuration);
    }
};

TEST_CASE("BackEndKvServer E2E: bidirectional idle timeout", "[silkworm][node][rpc]") {
    TxIdleTimeoutGuard timeout_guard{10};
    NodeSettings node_settings;
    BackEndKvE2eTest test{silkworm::log::Level::kNone, node_settings};
    test.fill_tables();
    auto kv_client = *test.kv_client;

    SECTION("Tx KO: immediate finish", "[silkworm][node][rpc]") {
        grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        auto status = tx_reader_writer->Finish();
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::DEADLINE_EXCEEDED);
        CHECK(status.error_message().find("call idle, no incoming request") != std::string::npos);
    }

    SECTION("Tx KO: finish after first read", "[silkworm][node][rpc]") {
        grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        tx_reader_writer->Read(&response);
        CHECK(response.txid() != 0);
        auto status = tx_reader_writer->Finish();
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::DEADLINE_EXCEEDED);
        CHECK(status.error_message().find("call idle, no incoming request") != std::string::npos);
    }

    SECTION("Tx KO: finish after first read and one write/read", "[silkworm][node][rpc]") {
        grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        tx_reader_writer->Read(&response);
        CHECK(response.txid() != 0);
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        const bool write_ok = tx_reader_writer->Write(open);
        CHECK(write_ok);
        response.clear_txid();
        tx_reader_writer->Read(&response);
        CHECK(response.cursorid() != 0);
        auto status = tx_reader_writer->Finish();
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::DEADLINE_EXCEEDED);
        CHECK(status.error_message().find("call idle, no incoming request") != std::string::npos);
    }
}

TEST_CASE("BackEndKvServer E2E: Tx cursor valid operations", "[silkworm][node][rpc]") {
    BackEndKvE2eTest test{silkworm::log::Level::kNone};
    test.fill_tables();
    auto kv_client = *test.kv_client;

    SECTION("Tx OK: one FIRST operation", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, first, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(status.error_message().empty());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: two FIRST operations", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor first1;
        first1.set_op(remote::Op::FIRST);
        first1.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor first2;
        first2.set_op(remote::Op::FIRST);
        first2.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, first1, first2, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(status.error_message().empty());
        CHECK(responses.size() == 5);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].k() == "AA");
        CHECK(responses[3].v() == "00");
        CHECK(responses[4].cursorid() == 0);
    }

    SECTION("Tx OK: one LAST operation", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor last;
        last.set_op(remote::Op::LAST);
        last.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, last, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(status.error_message().empty());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: two LAST operations", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor last1;
        last1.set_op(remote::Op::LAST);
        last1.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor last2;
        last2.set_op(remote::Op::LAST);
        last2.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, last1, last2, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(status.error_message().empty());
        CHECK(responses.size() == 5);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].k() == "BB");
        CHECK(responses[3].v() == "11");
        CHECK(responses[4].cursorid() == 0);
    }

    SECTION("Tx OK: one NEXT operation", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor next;
        next.set_op(remote::Op::NEXT);
        next.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, next, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(status.error_message().empty());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: two NEXT operations", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor next1;
        next1.set_op(remote::Op::NEXT);
        next1.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor next2;
        next2.set_op(remote::Op::NEXT);
        next2.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, next1, next2, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(status.error_message().empty());
        CHECK(responses.size() == 5);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].k() == "BB");
        CHECK(responses[3].v() == "11");
        CHECK(responses[4].cursorid() == 0);
    }

    SECTION("Tx OK: two NEXT operations using different cursors", "[silkworm][node][rpc]") {
        remote::Cursor open1;
        open1.set_op(remote::Op::OPEN);
        open1.set_bucketname(kTestMap.name);
        remote::Cursor next1;
        next1.set_op(remote::Op::NEXT);
        next1.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close1;
        close1.set_op(remote::Op::CLOSE);
        close1.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor open2;
        open2.set_op(remote::Op::OPEN);
        open2.set_bucketname(kTestMap.name);
        remote::Cursor next2;
        next2.set_op(remote::Op::NEXT);
        next2.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close2;
        close2.set_op(remote::Op::CLOSE);
        close2.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open1, next1, close1, open2, next2, close2};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(status.error_message().empty());
        CHECK(responses.size() == 7);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursorid() == 0);
        CHECK(responses[4].cursorid() != 0);
        CHECK(responses[5].k() == "AA");
        CHECK(responses[5].v() == "00");
        CHECK(responses[6].cursorid() == 0);
    }

    SECTION("Tx OK: one PREV operation", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor prev;
        prev.set_op(remote::Op::PREV);
        prev.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, prev, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(status.error_message().empty());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: two PREV operations", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor prev1;
        prev1.set_op(remote::Op::PREV);
        prev1.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor prev2;
        prev2.set_op(remote::Op::PREV);
        prev2.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, prev1, prev2, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(status.error_message().empty());
        CHECK(responses.size() == 5);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].k() == "AA");
        CHECK(responses[3].v() == "00");
        CHECK(responses[4].cursorid() == 0);
    }

    SECTION("Tx OK: two PREV operations using different cursors", "[silkworm][node][rpc]") {
        remote::Cursor open1;
        open1.set_op(remote::Op::OPEN);
        open1.set_bucketname(kTestMap.name);
        remote::Cursor prev1;
        prev1.set_op(remote::Op::PREV);
        prev1.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close1;
        close1.set_op(remote::Op::CLOSE);
        close1.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor open2;
        open2.set_op(remote::Op::OPEN);
        open2.set_bucketname(kTestMap.name);
        remote::Cursor prev2;
        prev2.set_op(remote::Op::PREV);
        prev2.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close2;
        close2.set_op(remote::Op::CLOSE);
        close2.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open1, prev1, close1, open2, prev2, close2};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(status.error_message().empty());
        CHECK(responses.size() == 7);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].cursorid() == 0);
        CHECK(responses[4].cursorid() != 0);
        CHECK(responses[5].k() == "BB");
        CHECK(responses[5].v() == "11");
        CHECK(responses[6].cursorid() == 0);
    }

    SECTION("Tx OK: FIRST + CURRENT operations on multi-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor current;
        current.set_op(remote::Op::CURRENT);
        current.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, first, current, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 5);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].k() == "AA");
        CHECK(responses[3].v() == "00");
        CHECK(responses[4].cursorid() == 0);
    }

    SECTION("Tx OK: LAST + CURRENT operations on multi-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor last;
        last.set_op(remote::Op::LAST);
        last.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor current;
        current.set_op(remote::Op::CURRENT);
        current.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, last, current, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 5);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].k() == "BB");
        CHECK(responses[3].v() == "22");
        CHECK(responses[4].cursorid() == 0);
    }

    SECTION("Tx OK: FIRST + FIRST_DUP operations on multi-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor first_dup;
        first_dup.set_op(remote::Op::FIRST_DUP);
        first_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, first, first_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 5);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].k().empty());
        CHECK(responses[3].v() == "00");
        CHECK(responses[4].cursorid() == 0);
    }

    SECTION("Tx OK: LAST + FIRST_DUP operations on multi-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor last;
        last.set_op(remote::Op::LAST);
        last.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor first_dup;
        first_dup.set_op(remote::Op::FIRST_DUP);
        first_dup.set_cursor(0); // automatically assigned by KvClient::tx
        first_dup.set_k("AA");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, last, first_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 5);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].k().empty());
        CHECK(responses[3].v() == "22");
        CHECK(responses[4].cursorid() == 0);
    }

    SECTION("Tx OK: one FIRST + two NEXT_DUP operations on multi-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor next_dup1;
        next_dup1.set_op(remote::Op::NEXT_DUP);
        next_dup1.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor next_dup2;
        next_dup2.set_op(remote::Op::NEXT_DUP);
        next_dup2.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, first, next_dup1, next_dup2, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 6);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].k() == "AA");
        CHECK(responses[3].v() == "11");
        CHECK(responses[4].k() == "AA");
        CHECK(responses[4].v() == "22");
        CHECK(responses[5].cursorid() == 0);
    }

    SECTION("Tx OK: NEXT_DUP operation on single-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor next_dup;
        next_dup.set_op(remote::Op::NEXT_DUP);
        next_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, next_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: one PREV_DUP operation on single-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor prev_dup;
        prev_dup.set_op(remote::Op::PREV_DUP);
        prev_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, prev_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: one NEXT_DUP operation on multi-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor next_dup;
        next_dup.set_op(remote::Op::NEXT_DUP);
        next_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, next_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: one PREV_DUP operation on multi-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor prev_dup;
        prev_dup.set_op(remote::Op::PREV_DUP);
        prev_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, prev_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: one FIRST + one LAST_DUP operation on multi-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor last_dup;
        last_dup.set_op(remote::Op::LAST_DUP);
        last_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, first, last_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 5);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].k().empty());
        CHECK(responses[3].v() == "22");
        CHECK(responses[4].cursorid() == 0);
    }

    SECTION("Tx OK: one LAST + one LAST_DUP operation on multi-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor last;
        last.set_op(remote::Op::LAST);
        last.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor last_dup;
        last_dup.set_op(remote::Op::LAST_DUP);
        last_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, last, last_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 5);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].k().empty());
        CHECK(responses[3].v() == "22");
        CHECK(responses[4].cursorid() == 0);
    }

    SECTION("Tx OK: one NEXT_NO_DUP operation on multi-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor next_no_dup;
        next_no_dup.set_op(remote::Op::NEXT_NO_DUP);
        next_no_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, next_no_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: one PREV_NO_DUP operation on multi-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor prev_no_dup;
        prev_no_dup.set_op(remote::Op::PREV_NO_DUP);
        prev_no_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, prev_no_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: SEEK operation w/o key on single-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek;
        seek.set_op(remote::Op::SEEK);
        seek.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: SEEK operation w/ existent key on single-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek;
        seek.set_op(remote::Op::SEEK);
        seek.set_cursor(0); // automatically assigned by KvClient::tx
        seek.set_k("BB");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: SEEK operation w/ unexistent key on single-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek;
        seek.set_op(remote::Op::SEEK);
        seek.set_cursor(0); // automatically assigned by KvClient::tx
        seek.set_k("ZZ");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v().empty());
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: SEEK_EXACT operation w/o key on single-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek_exact;
        seek_exact.set_op(remote::Op::SEEK_EXACT);
        seek_exact.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_exact, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v().empty());
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: SEEK_EXACT operation w/ existent key on single-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek_exact;
        seek_exact.set_op(remote::Op::SEEK_EXACT);
        seek_exact.set_cursor(0); // automatically assigned by KvClient::tx
        seek_exact.set_k("BB");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_exact, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v().empty());
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: SEEK_EXACT operation w/ unexistent key on single-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek_exact;
        seek_exact.set_op(remote::Op::SEEK_EXACT);
        seek_exact.set_cursor(0); // automatically assigned by KvClient::tx
        seek_exact.set_k("ZZ");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_exact, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v().empty());
        CHECK(responses[3].cursorid() == 0);
    }
}

TEST_CASE("BackEndKvServer E2E: Tx cursor invalid operations", "[silkworm][node][rpc]") {
    BackEndKvE2eTest test{silkworm::log::Level::kNone};
    test.fill_tables();
    auto kv_client = *test.kv_client;

    SECTION("Tx KO: CURRENT operation", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor current;
        current.set_op(remote::Op::CURRENT);
        current.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, current, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INTERNAL);
        CHECK(status.error_message().find("exception: MDBX_ENODATA") != std::string::npos);
        CHECK(responses.size() == 2);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
    }

    SECTION("Tx KO: FIRST_DUP operation on single-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor first_dup;
        first_dup.set_op(remote::Op::FIRST_DUP);
        first_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, first, first_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INTERNAL);
        CHECK(status.error_message().find("exception: MDBX_INCOMPATIBLE") != std::string::npos);
        CHECK(responses.size() == 3);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
    }

    SECTION("Tx KO: LAST_DUP operation on single-value table", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor last_dup;
        last_dup.set_op(remote::Op::LAST_DUP);
        last_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, first, last_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INTERNAL);
        CHECK(status.error_message().find("exception: MDBX_INCOMPATIBLE") != std::string::npos);
        CHECK(responses.size() == 3);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
    }

    SECTION("Tx KO: FIRST_DUP operation w/o positioned key", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor first_dup;
        first_dup.set_op(remote::Op::FIRST_DUP);
        first_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, first_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INTERNAL);
        CHECK(status.error_message().find("exception: mdbx") != std::string::npos);
        CHECK(responses.size() == 2);
        CHECK(responses[0].txid() != 0);
    }

    SECTION("Tx KO: LAST_DUP operation w/o positioned key", "[silkworm][node][rpc]") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor last_dup;
        last_dup.set_op(remote::Op::LAST_DUP);
        last_dup.set_cursor(0); // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0); // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, last_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INTERNAL);
        CHECK(status.error_message().find("exception: mdbx") != std::string::npos);
        CHECK(responses.size() == 2);
        CHECK(responses[0].txid() != 0);
    }
}

class TxMaxTimeToLiveGuard {
  public:
    explicit TxMaxTimeToLiveGuard(uint8_t t) {
        TxCall::set_max_ttl_duration(boost::posix_time::milliseconds{t});
    }
    ~TxMaxTimeToLiveGuard() {
        TxCall::set_max_ttl_duration(kMaxTxDuration);
    }
};

TEST_CASE("BackEndKvServer E2E: bidirectional max TTL duration", "[silkworm][node][rpc]") {
    constexpr uint8_t kCustomMaxTimeToLive{10};
    TxMaxTimeToLiveGuard ttl_guard{kCustomMaxTimeToLive};
    NodeSettings node_settings;
    BackEndKvE2eTest test{silkworm::log::Level::kNone, node_settings};
    test.fill_tables();
    auto kv_client = *test.kv_client;

    SECTION("Tx: cursor NEXT ops across renew are consecutive", "[silkworm][node][rpc]") {
        grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        tx_reader_writer->Read(&response);
        CHECK(response.txid() != 0);
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        CHECK(tx_reader_writer->Write(open));
        response.clear_txid();
        tx_reader_writer->Read(&response);
        const auto cursor_id = response.cursorid();
        CHECK(cursor_id != 0);
        remote::Cursor next1;
        next1.set_op(remote::Op::NEXT);
        next1.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next1));
        response.clear_cursorid();
        tx_reader_writer->Read(&response);
        CHECK(response.k() == "AA");
        CHECK(response.v() == "00");
        std::this_thread::sleep_for(std::chrono::milliseconds{kCustomMaxTimeToLive});
        remote::Cursor next2;
        next2.set_op(remote::Op::NEXT);
        next2.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next2));
        response.clear_cursorid();
        tx_reader_writer->Read(&response);
        CHECK(response.k() == "BB");
        CHECK(response.v() == "11");
        tx_reader_writer->WritesDone();
        auto status = tx_reader_writer->Finish();
        CHECK(status.ok());
    }

    SECTION("Tx: cursor NEXT_DUP ops across renew are consecutive", "[silkworm][node][rpc]") {
        grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        tx_reader_writer->Read(&response);
        CHECK(response.txid() != 0);
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        CHECK(tx_reader_writer->Write(open));
        response.clear_txid();
        tx_reader_writer->Read(&response);
        const auto cursor_id = response.cursorid();
        CHECK(cursor_id != 0);
        remote::Cursor next_dup1;
        next_dup1.set_op(remote::Op::NEXT_DUP);
        next_dup1.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next_dup1));
        response.clear_cursorid();
        tx_reader_writer->Read(&response);
        CHECK(response.k() == "AA");
        CHECK(response.v() == "00");
        std::this_thread::sleep_for(std::chrono::milliseconds{kCustomMaxTimeToLive});
        remote::Cursor next_dup2;
        next_dup2.set_op(remote::Op::NEXT_DUP);
        next_dup2.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next_dup2));
        response.clear_cursorid();
        tx_reader_writer->Read(&response);
        CHECK(response.k() == "AA");
        CHECK(response.v() == "11");
        tx_reader_writer->WritesDone();
        auto status = tx_reader_writer->Finish();
        CHECK(status.ok());
    }
}

} // namespace silkworm::rpc
