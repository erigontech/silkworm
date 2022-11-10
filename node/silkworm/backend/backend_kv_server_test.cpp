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
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch.hpp>
#include <types/types.pb.h>

#include <silkworm/backend/ethereum_backend.hpp>
#include <silkworm/backend/state_change_collection.hpp>
#include <silkworm/common/base.hpp>
#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/rpc/common/conversion.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/test/log.hpp>

using namespace std::chrono_literals;

namespace {  // Trick suggested by gRPC team to avoid name clashes in multiple test modules
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

    auto tx_start(grpc::ClientContext* context) { return stub_->Tx(context); }

    auto statechanges_start(grpc::ClientContext* context, const remote::StateChangeRequest& request) {
        return stub_->StateChanges(context, request);
    }

  private:
    remote::KV::StubInterface* stub_;
};

class ThreadedKvClient {
  public:
    //! It is safe to call this method *only after* join_and_finish() has been called
    std::vector<remote::StateChangeBatch> responses() const { return responses_; }

    void start_and_consume_statechanges(KvClient client) {
        // Start StateChanges server-streaming call on calling thread
        remote::StateChangeRequest request;
        statechangebatch_reader_ = client.statechanges_start(&context_, request);

        // We need a dedicated thread to consume the incoming messages because only one (blocking)
        // Read completion will tell us that server-side subscription really happened. This machinery
        // is needed just in these all-in-one tests
        consumer_thread_ = std::thread{[&]() {
            bool has_more{true};
            do {
                has_more = statechangebatch_reader_->Read(&responses_.emplace_back());
                // As soon as the first Read has completed, we know for sure that subscription has occurred
                std::unique_lock subscribed_lock{subscribed_mutex_};
                if (!subscribed_) {
                    subscribed_ = true;
                    subscribed_lock.unlock();
                    subscribed_condition_.notify_one();
                }
            } while (has_more);
            // Last response read is void so discard it
            responses_.pop_back();
        }};
    }

    bool wait_one_milli_for_subscription() {
        std::unique_lock subscribed_lock{subscribed_mutex_};
        return subscribed_condition_.wait_for(subscribed_lock, 1ms, [&] { return subscribed_; });
    }

    grpc::Status join_and_finish() {
        consumer_thread_.join();
        return statechangebatch_reader_->Finish();
    }

  private:
    grpc::ClientContext context_;
    std::unique_ptr<grpc::ClientReaderInterface<remote::StateChangeBatch>> statechangebatch_reader_;
    std::thread consumer_thread_;
    std::mutex subscribed_mutex_;
    std::condition_variable subscribed_condition_;
    bool subscribed_{false};
    std::vector<remote::StateChangeBatch> responses_;
};

const uint64_t kTestSentryPeerCount{10};
constexpr const char* kTestSentryPeerId{"peer_id"};
constexpr const char* kTestSentryPeerName{"peer_name"};

class SentryServer {
  public:
    explicit SentryServer(grpc::Status status) : status_(std::move(status)) {}

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
        service_.RequestPeerCount(&pc_context, &pc_request, &pc_responder, cq_.get(), cq_.get(),
                                  PEER_COUNT_REQUEST_TAG);
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
const std::string kTestAddressUri{"localhost:12345"};

const std::string kTestSentryAddress1{"localhost:54321"};
const std::string kTestSentryAddress2{"localhost:54322"};

const silkworm::db::MapConfig kTestMap{"TestTable"};
const silkworm::db::MapConfig kTestMultiMap{"TestMultiTable", mdbx::key_mode::usual, mdbx::value_mode::multi};

using namespace silkworm;

using StateChangeTokenObserver = std::function<void(std::optional<StateChangeToken>)>;

struct TestableStateChangeCollection : public StateChangeCollection {
    std::optional<StateChangeToken> subscribe(StateChangeConsumer consumer, StateChangeFilter filter) override {
        const auto token = StateChangeCollection::subscribe(consumer, filter);
        if (token_observer_) {
            token_observer_(token);
        }
        return token;
    }

    void set_token(StateChangeToken next_token) { next_token_ = next_token; }

    void register_token_observer(StateChangeTokenObserver token_observer) { token_observer_ = std::move(token_observer); }

    StateChangeTokenObserver token_observer_;
};

class TestableEthereumBackEnd : public EthereumBackEnd {
  public:
    TestableEthereumBackEnd(const NodeSettings& node_settings, mdbx::env* chaindata_env)
        : EthereumBackEnd(node_settings, chaindata_env, std::make_unique<TestableStateChangeCollection>()) {}

    [[nodiscard]] TestableStateChangeCollection* state_change_source_for_test() const noexcept {
        return dynamic_cast<TestableStateChangeCollection*>(EthereumBackEnd::state_change_source());
    }
};

struct BackEndKvE2eTest {
    explicit BackEndKvE2eTest(silkworm::log::Level log_verbosity, NodeSettings&& options = {},
                              std::vector<grpc::Status> statuses = {grpc::Status::OK})
        : set_verbosity_log_guard{log_verbosity} {
        std::shared_ptr<grpc::Channel> channel =
            grpc::CreateChannel(kTestAddressUri, grpc::InsecureChannelCredentials());
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

        // Default value for external Sentry address(es) must be erased in tests to avoid conflict on port
        if (options.external_sentry_addr == "127.0.0.1:9091") {
            options.external_sentry_addr.clear();
        }

        backend = std::make_unique<TestableEthereumBackEnd>(options, &database_env);
        server = std::make_unique<rpc::BackEndKvServer>(srv_config, *backend);
        server->build_and_start();

        std::stringstream sentry_list_stream{options.external_sentry_addr};
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

    test::SetLogVerbosityGuard set_verbosity_log_guard;
    rpc::Grpc2SilkwormLogGuard grpc2silkworm_log_guard;
    std::unique_ptr<remote::ETHBACKEND::Stub> ethbackend_stub;
    std::unique_ptr<BackEndClient> backend_client;
    std::unique_ptr<remote::KV::Stub> kv_stub;
    std::unique_ptr<KvClient> kv_client;
    rpc::ServerConfig srv_config;
    TemporaryDirectory tmp_dir;
    std::unique_ptr<db::EnvConfig> db_config;
    mdbx::env_managed database_env;
    std::unique_ptr<TestableEthereumBackEnd> backend;
    std::unique_ptr<rpc::BackEndKvServer> server;
    std::vector<std::unique_ptr<SentryServer>> sentry_servers;
};
}  // namespace

namespace silkworm::rpc {

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE("BackEndKvServer", "[silkworm][node][rpc]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
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

    SECTION("BackEndKvServer::BackEndKvServer OK: create/destroy server") {
        BackEndKvServer server{srv_config, backend};
    }

    SECTION("BackEndKvServer::BackEndKvServer OK: create/shutdown/destroy server") {
        BackEndKvServer server{srv_config, backend};
        server.shutdown();
    }

    SECTION("BackEndKvServer::build_and_start OK: run server in separate thread") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        std::thread server_thread{[&server]() { server.join(); }};
        server.shutdown();
        server_thread.join();
    }

    SECTION("BackEndKvServer::build_and_start OK: create/shutdown/run/destroy server") {
        BackEndKvServer server{srv_config, backend};
        server.shutdown();
        server.build_and_start();
    }

    SECTION("BackEndKvServer::shutdown OK: shutdown server not running") {
        BackEndKvServer server{srv_config, backend};
        server.shutdown();
    }

    SECTION("BackEndKvServer::shutdown OK: shutdown twice server not running") {
        BackEndKvServer server{srv_config, backend};
        server.shutdown();
        server.shutdown();
    }

    SECTION("BackEndKvServer::shutdown OK: shutdown running server") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        server.shutdown();
        server.join();
    }

    SECTION("BackEndKvServer::shutdown OK: shutdown twice running server") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        server.shutdown();
        server.shutdown();
        server.join();
    }

    SECTION("BackEndKvServer::shutdown OK: shutdown running server again after join") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        server.shutdown();
        server.join();
        server.shutdown();
    }

    SECTION("BackEndKvServer::join OK: shutdown joined server") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        std::thread server_thread{[&server]() { server.join(); }};
        server.shutdown();
        server_thread.join();
    }

    SECTION("BackEndKvServer::join OK: shutdown joined server and join again") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        std::thread server_thread{[&server]() { server.join(); }};
        server.shutdown();
        server_thread.join();
        server.join();  // cannot move before server_thread.join() due to data race in boost::asio::detail::posix_thread
    }
}

TEST_CASE("BackEndKvServer E2E: empty node settings", "[silkworm][node][rpc]") {
    BackEndKvE2eTest test{silkworm::log::Level::kNone};
    auto backend_client = *test.backend_client;

    SECTION("Etherbase: return missing coinbase error") {
        remote::EtherbaseReply response;
        const auto status = backend_client.etherbase(&response);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INTERNAL);
        CHECK(status.error_message() == "etherbase must be explicitly specified");
        CHECK(!response.has_address());
    }

    SECTION("NetVersion: return out-of-range network ID") {
        remote::NetVersionReply response;
        const auto status = backend_client.net_version(&response);
        CHECK(status.ok());
        CHECK(response.id() == 0);
    }

    SECTION("NetPeerCount: return zero peer count") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status.ok());
        CHECK(response.count() == 0);
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
        CHECK(response.nodename().find("silkworm") != std::string::npos);
    }

    // TODO(canepat): change using something meaningful when really implemented
    SECTION("Subscribe: return streamed subscriptions") {
        remote::SubscribeRequest request;
        std::vector<remote::SubscribeReply> responses;
        const auto status = backend_client.subscribe_and_consume(request, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 2);
    }

    SECTION("NodeInfo: return information about zero nodes") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status.ok());
        CHECK(response.nodesinfo_size() == 0);
    }
}

TEST_CASE("BackEndKvServer E2E: KV", "[silkworm][node][rpc]") {
    BackEndKvE2eTest test{silkworm::log::Level::kNone};
    auto kv_client = *test.kv_client;

    SECTION("Version: return KV version") {
        types::VersionReply response;
        const auto status = kv_client.version(&response);
        CHECK(status.ok());
        CHECK(response.major() == 5);
        CHECK(response.minor() == 1);
        CHECK(response.patch() == 0);
    }

    SECTION("Tx KO: empty table name") {
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

    SECTION("Tx KO: invalid table name") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname("NonexistentTable");
        std::vector<remote::Cursor> requests{open};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
        CHECK(status.error_message().find("unknown bucket") != std::string::npos);
        CHECK(responses.size() == 1);
        CHECK(responses[0].txid() != 0);
    }

    SECTION("Tx KO: missing operation") {
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

    SECTION("Tx OK: just start then finish") {
        std::vector<remote::Cursor> requests{};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 1);
        CHECK(responses[0].txid() != 0);
    }

    SECTION("Tx OK: cursor opened") {
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

    SECTION("Tx OK: cursor opened then closed") {
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

    SECTION("Tx KO: cursor opened then unknown") {
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

    SECTION("Tx OK: one FIRST operation on empty table gives empty result") {
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

    SECTION("Tx KO: one NEXT operation on empty table gives empty result") {
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

    SECTION("StateChanges OK: receive streamed state changes") {
        static constexpr uint64_t kTestPendingBaseFee{10'000};
        static constexpr uint64_t kTestGasLimit{10'000'000};
        auto* state_change_source = test.backend->state_change_source();

        ThreadedKvClient threaded_kv_client;

        // Start StateChanges server-streaming call and consume incoming messages on dedicated thread
        threaded_kv_client.start_and_consume_statechanges(kv_client);

        // Keep publishing state changes using the Catch2 thread until at least one has been received
        BlockNum block_number{0};
        bool publishing{true};
        while (publishing) {
            state_change_source->start_new_batch(++block_number, kEmptyHash, std::vector<Bytes>{}, /*unwind=*/false);
            state_change_source->notify_batch(kTestPendingBaseFee, kTestGasLimit);

            publishing = !threaded_kv_client.wait_one_milli_for_subscription();
        }
        // After at least one state change has been received, close the server-side RPC stream
        state_change_source->close();

        // then wait for consumer thread termination and get the client-side RPC result
        const auto status = threaded_kv_client.join_and_finish();

        CHECK(status.ok());
        CHECK(!threaded_kv_client.responses().empty());
    }

    SECTION("StateChanges OK: multiple concurrent subscriptions") {
        static constexpr uint64_t kTestPendingBaseFee{10'000};
        static constexpr uint64_t kTestGasLimit{10'000'000};
        auto* state_change_source = test.backend->state_change_source();

        ThreadedKvClient threaded_kv_client1, threaded_kv_client2;

        // Start StateChanges server-streaming call and consume incoming messages on dedicated thread
        threaded_kv_client1.start_and_consume_statechanges(kv_client);
        threaded_kv_client2.start_and_consume_statechanges(kv_client);

        // Keep publishing state changes using the Catch2 thread until at least one has been received
        BlockNum block_number{0};
        bool publishing{true};
        while (publishing) {
            state_change_source->start_new_batch(++block_number, kEmptyHash, {}, /*unwind=*/false);
            state_change_source->notify_batch(kTestPendingBaseFee, kTestGasLimit);

            publishing = !(threaded_kv_client1.wait_one_milli_for_subscription() &&
                           threaded_kv_client2.wait_one_milli_for_subscription());
        }
        // After at least one state change has been received, close the server-side RPC stream
        state_change_source->close();

        // then wait for consumer thread termination and get the client-side RPC result
        const auto status1 = threaded_kv_client1.join_and_finish();
        const auto status2 = threaded_kv_client2.join_and_finish();

        CHECK(status1.ok());
        CHECK(status2.ok());
        CHECK(!threaded_kv_client1.responses().empty());
        CHECK(!threaded_kv_client2.responses().empty());
    }

    SECTION("StateChanges KO: token already in use") {
        auto* state_change_source = test.backend->state_change_source_for_test();

        std::mutex token_reset_mutex;
        std::condition_variable token_reset_condition;
        bool token_reset{false};
        state_change_source->register_token_observer([&](std::optional<StateChangeToken> token) {
            if (token) {
                // Purposely reset the subscription token
                state_change_source->set_token(0);

                std::unique_lock token_reset_lock{token_reset_mutex};
                token_reset = true;
                token_reset_lock.unlock();
                token_reset_condition.notify_one();
            }
        });

        // Start a StateChanges server-streaming call
        grpc::ClientContext context1;
        remote::StateChangeRequest request1;
        auto subscribe_reply_reader1 = kv_client.statechanges_start(&context1, request1);

        // Wait for token reset condition to happen
        std::unique_lock token_reset_lock{token_reset_mutex};
        token_reset_condition.wait(token_reset_lock, [&] { return token_reset; });

        // Start another StateChanges server-streaming call and check it fails
        grpc::ClientContext context2;
        remote::StateChangeRequest request2;
        auto subscribe_reply_reader2 = kv_client.statechanges_start(&context2, request2);

        const auto status2 = subscribe_reply_reader2->Finish();
        CHECK(!status2.ok());
        CHECK(status2.error_code() == grpc::StatusCode::ALREADY_EXISTS);
        CHECK(status2.error_message().find("assigned consumer token already in use") != std::string::npos);

        // Close the server-side RPC stream and check first call completes successfully
        state_change_source->close();

        const auto status1 = subscribe_reply_reader1->Finish();
        CHECK(status1.ok());
    }
}

TEST_CASE("BackEndKvServer E2E: mainnet chain with zero etherbase", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.chain_config = *(silkworm::lookup_known_chain("mainnet")->second);
    node_settings.etherbase = evmc::address{};
    BackEndKvE2eTest test{silkworm::log::Level::kNone, std::move(node_settings)};
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

TEST_CASE("BackEndKvServer E2E: one Sentry status OK", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.external_sentry_addr = kTestSentryAddress1;
    BackEndKvE2eTest test{silkworm::log::Level::kNone, std::move(node_settings), {grpc::Status::OK}};
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
        CHECK(response.nodesinfo_size() == 1);
        CHECK(response.nodesinfo(0).id() == kTestSentryPeerId);
        CHECK(response.nodesinfo(0).name() == kTestSentryPeerName);
    }
}

TEST_CASE("BackEndKvServer E2E: one Sentry status KO", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.external_sentry_addr = kTestSentryAddress1;
    grpc::Status DEADLINE_EXCEEDED_ERROR{grpc::StatusCode::DEADLINE_EXCEEDED, "timeout"};
    BackEndKvE2eTest test{silkworm::log::Level::kNone, std::move(node_settings), {DEADLINE_EXCEEDED_ERROR}};
    auto backend_client = *test.backend_client;

    SECTION("NetPeerCount: return expected status error") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status == DEADLINE_EXCEEDED_ERROR);
    }

    SECTION("NodeInfo: return expected status error") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status == DEADLINE_EXCEEDED_ERROR);
    }
}

TEST_CASE("BackEndKvServer E2E: more than one Sentry all status OK", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.external_sentry_addr = kTestSentryAddress1 + "," + kTestSentryAddress2;
    BackEndKvE2eTest test{silkworm::log::Level::kNone, std::move(node_settings), {grpc::Status::OK, grpc::Status::OK}};
    auto backend_client = *test.backend_client;

    SECTION("NetPeerCount: return peer count") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status.ok());
        CHECK(response.count() == 2 * kTestSentryPeerCount);
    }

    SECTION("NodeInfo: return information about nodes") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status.ok());
        CHECK(response.nodesinfo_size() == 2);
        for (int i{0}; i < response.nodesinfo_size(); i++) {
            const types::NodeInfoReply& nodes_info = response.nodesinfo(i);
            CHECK(nodes_info.id() == kTestSentryPeerId);
            CHECK(nodes_info.name() == kTestSentryPeerName);
        }
    }
}

TEST_CASE("BackEndKvServer E2E: more than one Sentry at least one status KO", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.external_sentry_addr = kTestSentryAddress1 + "," + kTestSentryAddress2;
    BackEndKvE2eTest test{silkworm::log::Level::kNone, std::move(node_settings), {grpc::Status::OK, grpc::Status::CANCELLED}};
    auto backend_client = *test.backend_client;

    SECTION("NetPeerCount: return expected status error") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status == grpc::Status::CANCELLED);
    }

    SECTION("NodeInfo: return expected status error") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status == grpc::Status::CANCELLED);
    }
}

TEST_CASE("BackEndKvServer E2E: more than one Sentry all status KO", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    node_settings.external_sentry_addr = kTestSentryAddress1 + "," + kTestSentryAddress2;
    grpc::Status INTERNAL_ERROR{grpc::StatusCode::INTERNAL, "internal error"};
    grpc::Status INVALID_ARGUMENT_ERROR{grpc::StatusCode::INVALID_ARGUMENT, "invalid"};
    BackEndKvE2eTest test{silkworm::log::Level::kNone, std::move(node_settings), {INTERNAL_ERROR, INVALID_ARGUMENT_ERROR}};
    auto backend_client = *test.backend_client;

    SECTION("NetPeerCount: return expected status error") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK((status == INTERNAL_ERROR || status == INVALID_ARGUMENT_ERROR));
    }

    SECTION("NodeInfo: return expected status error") {
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
        BackEndKvE2eTest test{silkworm::log::Level::kError, std::move(node_settings)};
        test.fill_tables();
        auto kv_client = *test.kv_client;

        // Start many Tx calls w/o reading responses after writing requests.
        for (uint32_t i{0}; i < kNumTxs; i++) {
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
    // Server-side life cycle of Tx calls must be OK.
}

TEST_CASE("BackEndKvServer E2E: Tx max simultaneous readers exceeded", "[silkworm][node][rpc]") {
    NodeSettings node_settings;
    BackEndKvE2eTest test{silkworm::log::Level::kNone, std::move(node_settings)};
    test.fill_tables();
    auto kv_client = *test.kv_client;

    // Start and keep open as many Tx calls as the maximum number of readers.
    std::vector<std::unique_ptr<grpc::ClientContext>> client_contexts;
    std::vector<TxStreamPtr> tx_streams;
    for (uint32_t i{0}; i < test.database_env.get_info().mi_maxreaders; i++) {
        auto& context = client_contexts.emplace_back(std::make_unique<grpc::ClientContext>());
        auto tx_stream = kv_client.tx_start(context.get());
        // You must read at least the first unsolicited incoming message (TxID announcement).
        remote::Pair response;
        REQUIRE(tx_stream->Read(&response));
        REQUIRE(response.txid() != 0);
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
        REQUIRE(tx_stream->WritesDone());
        auto status = tx_stream->Finish();
        REQUIRE(status.ok());
    }
}

TEST_CASE("BackEndKvServer E2E: Tx max opened cursors exceeded", "[silkworm][node][rpc]") {
    BackEndKvE2eTest test{silkworm::log::Level::kNone, NodeSettings{}};
    test.fill_tables();
    auto kv_client = *test.kv_client;

    grpc::ClientContext context;
    const auto tx_stream = kv_client.tx_start(&context);
    // You must read at least the first unsolicited incoming message (TxID announcement).
    remote::Pair response;
    REQUIRE(tx_stream->Read(&response));
    REQUIRE(response.txid() != 0);
    response.clear_txid();
    // Open as many cursors as possible expecting successful result.
    for (uint32_t i{0}; i < kMaxTxCursors; i++) {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        REQUIRE(tx_stream->Write(open));
        response.clear_cursorid();
        REQUIRE(tx_stream->Read(&response));
        REQUIRE(response.cursorid() != 0);
    }
    // Try to open one more and get failure from server-side on the stream.
    remote::Cursor open;
    open.set_op(remote::Op::OPEN);
    open.set_bucketname(kTestMap.name);
    REQUIRE(tx_stream->Write(open));
    response.clear_cursorid();
    REQUIRE(!tx_stream->Read(&response));
    REQUIRE(response.cursorid() == 0);
    // Half-close the stream and complete the call checking expected failure.
    REQUIRE(tx_stream->WritesDone());
    auto status = tx_stream->Finish();
    CHECK(!status.ok());
    CHECK(status.error_code() == grpc::StatusCode::RESOURCE_EXHAUSTED);
    CHECK(status.error_message().find("maximum cursors per txn") != std::string::npos);
}

class TxIdleTimeoutGuard {
  public:
    explicit TxIdleTimeoutGuard(uint8_t t) { TxCall::set_max_idle_duration(std::chrono::milliseconds{t}); }
    ~TxIdleTimeoutGuard() { TxCall::set_max_idle_duration(server::kDefaultMaxIdleDuration); }
};

TEST_CASE("BackEndKvServer E2E: bidirectional idle timeout", "[silkworm][node][rpc]") {
    TxIdleTimeoutGuard timeout_guard{100};
    BackEndKvE2eTest test{silkworm::log::Level::kNone, NodeSettings{}};
    test.fill_tables();
    auto kv_client = *test.kv_client;

    // This commented test *blocks* starting from gRPC 1.44.0-p0 (works using gRPC 1.38.0-p0)
    // The reason could be that according to gRPC API spec this is kind of API misuse: it is
    // *appropriate* to call Finish only after all incoming messages have been read (not the
    // case here, missing tx ID announcement read) *and* no outgoing messages need to be sent.
    /*SECTION("Tx KO: immediate finish", "[.]") {
        grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        auto status = tx_reader_writer->Finish();
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::DEADLINE_EXCEEDED);
        CHECK(status.error_message().find("call idle, no incoming request") != std::string::npos);
    }*/

    SECTION("Tx KO: finish after first read (w/o WritesDone)") {
        grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.txid() != 0);
        auto status = tx_reader_writer->Finish();
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::DEADLINE_EXCEEDED);
        CHECK(status.error_message().find("no incoming request") != std::string::npos);
    }

    SECTION("Tx KO: finish after first read and one write/read (w/o WritesDone)") {
        grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.txid() != 0);
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        CHECK(tx_reader_writer->Write(open));
        response.clear_txid();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.cursorid() != 0);
        auto status = tx_reader_writer->Finish();
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::DEADLINE_EXCEEDED);
        CHECK(status.error_message().find("no incoming request") != std::string::npos);
    }
}

TEST_CASE("BackEndKvServer E2E: Tx cursor valid operations", "[silkworm][node][rpc]") {
    BackEndKvE2eTest test{silkworm::log::Level::kNone};
    test.fill_tables();
    auto kv_client = *test.kv_client;

    SECTION("Tx OK: one FIRST operation") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: two FIRST operations") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor first1;
        first1.set_op(remote::Op::FIRST);
        first1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor first2;
        first2.set_op(remote::Op::FIRST);
        first2.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: one LAST operation") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor last;
        last.set_op(remote::Op::LAST);
        last.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: two LAST operations") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor last1;
        last1.set_op(remote::Op::LAST);
        last1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor last2;
        last2.set_op(remote::Op::LAST);
        last2.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: one NEXT operation") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor next;
        next.set_op(remote::Op::NEXT);
        next.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: two NEXT operations") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor next1;
        next1.set_op(remote::Op::NEXT);
        next1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor next2;
        next2.set_op(remote::Op::NEXT);
        next2.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: two NEXT operations using different cursors") {
        remote::Cursor open1;
        open1.set_op(remote::Op::OPEN);
        open1.set_bucketname(kTestMap.name);
        remote::Cursor next1;
        next1.set_op(remote::Op::NEXT);
        next1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close1;
        close1.set_op(remote::Op::CLOSE);
        close1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor open2;
        open2.set_op(remote::Op::OPEN);
        open2.set_bucketname(kTestMap.name);
        remote::Cursor next2;
        next2.set_op(remote::Op::NEXT);
        next2.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close2;
        close2.set_op(remote::Op::CLOSE);
        close2.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: one PREV operation") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor prev;
        prev.set_op(remote::Op::PREV);
        prev.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: two PREV operations") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor prev1;
        prev1.set_op(remote::Op::PREV);
        prev1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor prev2;
        prev2.set_op(remote::Op::PREV);
        prev2.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: two PREV operations using different cursors") {
        remote::Cursor open1;
        open1.set_op(remote::Op::OPEN);
        open1.set_bucketname(kTestMap.name);
        remote::Cursor prev1;
        prev1.set_op(remote::Op::PREV);
        prev1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close1;
        close1.set_op(remote::Op::CLOSE);
        close1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor open2;
        open2.set_op(remote::Op::OPEN);
        open2.set_bucketname(kTestMap.name);
        remote::Cursor prev2;
        prev2.set_op(remote::Op::PREV);
        prev2.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close2;
        close2.set_op(remote::Op::CLOSE);
        close2.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: FIRST + CURRENT operations on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor current;
        current.set_op(remote::Op::CURRENT);
        current.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: LAST + CURRENT operations on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor last;
        last.set_op(remote::Op::LAST);
        last.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor current;
        current.set_op(remote::Op::CURRENT);
        current.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: FIRST + FIRST_DUP operations on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor first_dup;
        first_dup.set_op(remote::Op::FIRST_DUP);
        first_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: LAST + FIRST_DUP operations on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor last;
        last.set_op(remote::Op::LAST);
        last.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor first_dup;
        first_dup.set_op(remote::Op::FIRST_DUP);
        first_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        first_dup.set_k("AA");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: one FIRST + two NEXT_DUP operations on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor next_dup1;
        next_dup1.set_op(remote::Op::NEXT_DUP);
        next_dup1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor next_dup2;
        next_dup2.set_op(remote::Op::NEXT_DUP);
        next_dup2.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: NEXT_DUP operation on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor next_dup;
        next_dup.set_op(remote::Op::NEXT_DUP);
        next_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: one PREV_DUP operation on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor prev_dup;
        prev_dup.set_op(remote::Op::PREV_DUP);
        prev_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: one NEXT_DUP operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor next_dup;
        next_dup.set_op(remote::Op::NEXT_DUP);
        next_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: one PREV_DUP operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor prev_dup;
        prev_dup.set_op(remote::Op::PREV_DUP);
        prev_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: one FIRST + one LAST_DUP operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor last_dup;
        last_dup.set_op(remote::Op::LAST_DUP);
        last_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: one LAST + one LAST_DUP operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor last;
        last.set_op(remote::Op::LAST);
        last.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor last_dup;
        last_dup.set_op(remote::Op::LAST_DUP);
        last_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: one NEXT_NO_DUP operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor next_no_dup;
        next_no_dup.set_op(remote::Op::NEXT_NO_DUP);
        next_no_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: one PREV_NO_DUP operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor prev_no_dup;
        prev_no_dup.set_op(remote::Op::PREV_NO_DUP);
        prev_no_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: SEEK operation w/o key on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek;
        seek.set_op(remote::Op::SEEK);
        seek.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: SEEK operation w/ existent key on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek;
        seek.set_op(remote::Op::SEEK);
        seek.set_cursor(0);  // automatically assigned by KvClient::tx
        seek.set_k("BB");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: SEEK operation w/ unexisting key on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek;
        seek.set_op(remote::Op::SEEK);
        seek.set_cursor(0);  // automatically assigned by KvClient::tx
        seek.set_k("ZZ");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: SEEK_EXACT operation w/o key on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek_exact;
        seek_exact.set_op(remote::Op::SEEK_EXACT);
        seek_exact.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: SEEK_EXACT operation w/ existent key on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek_exact;
        seek_exact.set_op(remote::Op::SEEK_EXACT);
        seek_exact.set_cursor(0);  // automatically assigned by KvClient::tx
        seek_exact.set_k("BB");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: SEEK_EXACT operation w/ nonexistent key on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek_exact;
        seek_exact.set_op(remote::Op::SEEK_EXACT);
        seek_exact.set_cursor(0);  // automatically assigned by KvClient::tx
        seek_exact.set_k("ZZ");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx OK: one SEEK_BOTH w/o key operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor seek_both;
        seek_both.set_op(remote::Op::SEEK_BOTH);
        seek_both.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_both, close};
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

    SECTION("Tx OK: one SEEK_BOTH w/ nonexistent key operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor seek_both;
        seek_both.set_op(remote::Op::SEEK_BOTH);
        seek_both.set_cursor(0);  // automatically assigned by KvClient::tx
        seek_both.set_k("CC");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_both, close};
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

    SECTION("Tx OK: one SEEK_BOTH w/ existent key operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor seek_both;
        seek_both.set_op(remote::Op::SEEK_BOTH);
        seek_both.set_cursor(0);  // automatically assigned by KvClient::tx
        seek_both.set_k("AA");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_both, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: one SEEK_BOTH w/ existent key+value operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor seek_both;
        seek_both.set_op(remote::Op::SEEK_BOTH);
        seek_both.set_cursor(0);  // automatically assigned by KvClient::tx
        seek_both.set_k("AA");
        seek_both.set_v("22");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_both, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].cursorid() == 0);
    }

    SECTION("Tx OK: one SEEK_BOTH_EXACT w/o key operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor seek_both_exact;
        seek_both_exact.set_op(remote::Op::SEEK_BOTH_EXACT);
        seek_both_exact.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_both_exact, close};
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

    SECTION("Tx OK: one SEEK_BOTH_EXACT w/ nonexistent key operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor seek_both_exact;
        seek_both_exact.set_op(remote::Op::SEEK_BOTH_EXACT);
        seek_both_exact.set_cursor(0);  // automatically assigned by KvClient::tx
        seek_both_exact.set_k("CC");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_both_exact, close};
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

    SECTION("Tx OK: one SEEK_BOTH_EXACT w/ existent key operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor seek_both_exact;
        seek_both_exact.set_op(remote::Op::SEEK_BOTH_EXACT);
        seek_both_exact.set_cursor(0);  // automatically assigned by KvClient::tx
        seek_both_exact.set_k("AA");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_both_exact, close};
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

    SECTION("Tx OK: one SEEK_BOTH_EXACT w/ existent key+value operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor seek_both_exact;
        seek_both_exact.set_op(remote::Op::SEEK_BOTH_EXACT);
        seek_both_exact.set_cursor(0);  // automatically assigned by KvClient::tx
        seek_both_exact.set_k("AA");
        seek_both_exact.set_v("22");
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_both_exact, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 4);
        CHECK(responses[0].txid() != 0);
        CHECK(responses[1].cursorid() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].cursorid() == 0);
    }
}

TEST_CASE("BackEndKvServer E2E: Tx cursor invalid operations", "[silkworm][node][rpc]") {
    BackEndKvE2eTest test{silkworm::log::Level::kNone};
    test.fill_tables();
    auto kv_client = *test.kv_client;

    SECTION("Tx KO: CURRENT operation") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor current;
        current.set_op(remote::Op::CURRENT);
        current.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx KO: FIRST_DUP operation on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor first_dup;
        first_dup.set_op(remote::Op::FIRST_DUP);
        first_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx KO: LAST_DUP operation on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor last_dup;
        last_dup.set_op(remote::Op::LAST_DUP);
        last_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
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

    SECTION("Tx KO: FIRST_DUP operation w/o positioned key") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor first_dup;
        first_dup.set_op(remote::Op::FIRST_DUP);
        first_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, first_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INTERNAL);
        CHECK(status.error_message().find("exception: mdbx") != std::string::npos);
        CHECK(responses.size() == 2);
        CHECK(responses[0].txid() != 0);
    }

    SECTION("Tx KO: LAST_DUP operation w/o positioned key") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        remote::Cursor last_dup;
        last_dup.set_op(remote::Op::LAST_DUP);
        last_dup.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, last_dup, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INTERNAL);
        CHECK(status.error_message().find("exception: mdbx") != std::string::npos);
        CHECK(responses.size() == 2);
        CHECK(responses[0].txid() != 0);
    }

    SECTION("Tx KO: SEEK_BOTH operation on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek_both;
        seek_both.set_op(remote::Op::SEEK_BOTH);
        seek_both.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_both, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INTERNAL);
        CHECK(status.error_message().find("MDBX_INCOMPATIBLE") != std::string::npos);
        CHECK(responses.size() == 2);
        CHECK(responses[0].txid() != 0);
    }

    SECTION("Tx KO: SEEK_BOTH_EXACT operation on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        remote::Cursor seek_both_exact;
        seek_both_exact.set_op(remote::Op::SEEK_BOTH_EXACT);
        seek_both_exact.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);  // automatically assigned by KvClient::tx
        std::vector<remote::Cursor> requests{open, seek_both_exact, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INTERNAL);
        CHECK(status.error_message().find("MDBX_INCOMPATIBLE") != std::string::npos);
        CHECK(responses.size() == 2);
        CHECK(responses[0].txid() != 0);
    }
}

class TxMaxTimeToLiveGuard {
  public:
    explicit TxMaxTimeToLiveGuard(uint8_t t) { TxCall::set_max_ttl_duration(std::chrono::milliseconds{t}); }
    ~TxMaxTimeToLiveGuard() { TxCall::set_max_ttl_duration(kMaxTxDuration); }
};

TEST_CASE("BackEndKvServer E2E: bidirectional max TTL duration", "[silkworm][node][rpc]") {
    constexpr uint8_t kCustomMaxTimeToLive{100};
    TxMaxTimeToLiveGuard ttl_guard{kCustomMaxTimeToLive};
    BackEndKvE2eTest test{silkworm::log::Level::kNone, NodeSettings{}};
    test.fill_tables();
    auto kv_client = *test.kv_client;

    SECTION("Tx: cursor NEXT ops across renew are consecutive") {
        grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.txid() != 0);
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMap.name);
        CHECK(tx_reader_writer->Write(open));
        response.clear_txid();
        CHECK(tx_reader_writer->Read(&response));
        const auto cursor_id = response.cursorid();
        CHECK(cursor_id != 0);
        remote::Cursor next1;
        next1.set_op(remote::Op::NEXT);
        next1.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next1));
        response.clear_cursorid();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "00");
        std::this_thread::sleep_for(std::chrono::milliseconds{kCustomMaxTimeToLive});
        remote::Cursor next2;
        next2.set_op(remote::Op::NEXT);
        next2.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next2));
        response.clear_cursorid();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "BB");
        CHECK(response.v() == "11");
        tx_reader_writer->WritesDone();
        auto status = tx_reader_writer->Finish();
        CHECK(status.ok());
    }

    SECTION("Tx: cursor NEXT_DUP ops across renew are consecutive") {
        grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.txid() != 0);
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname(kTestMultiMap.name);
        CHECK(tx_reader_writer->Write(open));
        response.clear_txid();
        CHECK(tx_reader_writer->Read(&response));
        const auto cursor_id = response.cursorid();
        CHECK(cursor_id != 0);
        remote::Cursor next_dup1;
        next_dup1.set_op(remote::Op::NEXT_DUP);
        next_dup1.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next_dup1));
        response.clear_cursorid();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "00");
        std::this_thread::sleep_for(std::chrono::milliseconds{kCustomMaxTimeToLive});
        remote::Cursor next_dup2;
        next_dup2.set_op(remote::Op::NEXT_DUP);
        next_dup2.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next_dup2));
        response.clear_cursorid();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "11");
        tx_reader_writer->WritesDone();
        auto status = tx_reader_writer->Finish();
        CHECK(status.ok());
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc
