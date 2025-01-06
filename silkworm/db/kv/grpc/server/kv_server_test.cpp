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

#include "kv_server.hpp"

#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <absl/strings/match.h>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/os.hpp>
#include <silkworm/infra/grpc/common/util.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/interfaces/remote/kv.pb.h>
#include <silkworm/interfaces/types/types.pb.h>

#include "kv_calls.hpp"
#include "state_change_collection.hpp"

using namespace std::chrono_literals;

namespace {  // Trick suggested by gRPC team to avoid name clashes in multiple test modules

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
                cursor_id = responses.back().cursor_id();
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

    grpc::Status snapshots(const remote::SnapshotsRequest& request, remote::SnapshotsReply* response) {
        grpc::ClientContext context;
        return stub_->Snapshots(&context, request, response);
    }

    grpc::Status history_seek(const remote::HistorySeekReq& request, remote::HistorySeekReply* response) {
        grpc::ClientContext context;
        return stub_->HistorySeek(&context, request, response);
    }

    grpc::Status get_latest(const remote::GetLatestReq& request, remote::GetLatestReply* response) {
        grpc::ClientContext context;
        return stub_->GetLatest(&context, request, response);
    }

    grpc::Status index_range(const remote::IndexRangeReq& request, remote::IndexRangeReply* response) {
        grpc::ClientContext context;
        return stub_->IndexRange(&context, request, response);
    }

    grpc::Status history_range(const remote::HistoryRangeReq& request, remote::Pairs* response) {
        grpc::ClientContext context;
        return stub_->HistoryRange(&context, request, response);
    }

    grpc::Status range_as_of(const remote::RangeAsOfReq& request, remote::Pairs* response) {
        grpc::ClientContext context;
        return stub_->RangeAsOf(&context, request, response);
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

// TODO(canepat): better copy grpc_pick_unused_port_or_die to generate unused port
const std::string kTestAddressUri{"localhost:12345"};

const silkworm::datastore::kvdb::MapConfig kTestMap{"TestTable"};
const silkworm::datastore::kvdb::MapConfig kTestMultiMap{"TestMultiTable", mdbx::key_mode::usual, mdbx::value_mode::multi};

using namespace silkworm;

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

using KvServer = db::kv::grpc::server::KvServer;

struct KvEnd2EndTest {
    explicit KvEnd2EndTest() {
        log::init();
        std::shared_ptr<grpc::Channel> channel =
            grpc::CreateChannel(kTestAddressUri, grpc::InsecureChannelCredentials());
        kv_stub = remote::KV::NewStub(channel);
        kv_client = std::make_unique<KvClient>(kv_stub.get());

        srv_config.context_pool_settings.num_contexts = 1;
        srv_config.address_uri = kTestAddressUri;

        DataDirectory data_dir{tmp_dir.path()};
        REQUIRE_NOTHROW(data_dir.deploy());
        db_config = std::make_unique<datastore::kvdb::EnvConfig>();
        db_config->path = data_dir.chaindata().path().string();
        db_config->create = true;
        db_config->in_memory = true;
        database_env = datastore::kvdb::open_env(*db_config);
        auto rw_txn{database_env.start_write()};
        datastore::kvdb::open_map(rw_txn, kTestMap);
        datastore::kvdb::open_map(rw_txn, kTestMultiMap);
        rw_txn.commit();

        state_change_collection = std::make_unique<TestableStateChangeCollection>();
        server = std::make_unique<KvServer>(srv_config, datastore::kvdb::ROAccess{database_env}, state_change_collection.get());
        server->build_and_start();
    }

    void fill_tables() {
        auto rw_txn = database_env.start_write();
        datastore::kvdb::PooledCursor rw_cursor1{rw_txn, kTestMap};
        rw_cursor1.upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
        rw_cursor1.upsert(mdbx::slice{"BB"}, mdbx::slice{"11"});
        datastore::kvdb::PooledCursor rw_cursor2{rw_txn, kTestMultiMap};
        rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
        rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"11"});
        rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"22"});
        rw_cursor2.upsert(mdbx::slice{"BB"}, mdbx::slice{"22"});
        rw_txn.commit();
    }

    void alter_tables() {
        auto rw_txn = database_env.start_write();
        datastore::kvdb::PooledCursor rw_cursor1{rw_txn, kTestMap};
        rw_cursor1.upsert(mdbx::slice{"CC"}, mdbx::slice{"22"});
        datastore::kvdb::PooledCursor rw_cursor2{rw_txn, kTestMultiMap};
        rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"33"});
        rw_cursor2.upsert(mdbx::slice{"BB"}, mdbx::slice{"33"});
        rw_txn.commit();
    }

    ~KvEnd2EndTest() {
        server->shutdown();
        server->join();
    }

    std::unique_ptr<remote::KV::Stub> kv_stub;
    std::unique_ptr<KvClient> kv_client;
    rpc::ServerSettings srv_config;
    TemporaryDirectory tmp_dir;
    std::unique_ptr<datastore::kvdb::EnvConfig> db_config;
    mdbx::env_managed database_env;
    std::unique_ptr<TestableStateChangeCollection> state_change_collection;
    std::unique_ptr<KvServer> server;
};

}  // namespace

namespace silkworm::db::kv::grpc::server {

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE("KvServer", "[silkworm][node][rpc]") {
    log::init();
    rpc::ServerSettings srv_config;
    srv_config.address_uri = kTestAddressUri;
    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    REQUIRE_NOTHROW(data_dir.deploy());
    datastore::kvdb::EnvConfig db_config{data_dir.chaindata().path().string()};
    db_config.create = true;
    db_config.in_memory = true;
    auto chaindata_env = datastore::kvdb::open_env(db_config);
    ROAccess chaindata{chaindata_env};
    auto state_change_source{std::make_unique<TestableStateChangeCollection>()};

    SECTION("KvServer::KvServer OK: create/destroy server") {
        KvServer server{srv_config, chaindata, state_change_source.get()};
    }

    SECTION("KvServer::KvServer OK: create/shutdown/destroy server") {
        KvServer server{srv_config, chaindata, state_change_source.get()};
        server.shutdown();
    }

    SECTION("KvServer::build_and_start OK: run server in separate thread") {
        KvServer server{srv_config, chaindata, state_change_source.get()};
        server.build_and_start();
        std::thread server_thread{[&server]() { server.join(); }};
        server.shutdown();
        server_thread.join();
    }

    SECTION("KvServer::build_and_start OK: create/shutdown/run/destroy server") {
        KvServer server{srv_config, chaindata, state_change_source.get()};
        server.shutdown();
        server.build_and_start();
    }

    SECTION("KvServer::shutdown OK: shutdown server not running") {
        KvServer server{srv_config, chaindata, state_change_source.get()};
        server.shutdown();
    }

    SECTION("KvServer::shutdown OK: shutdown twice server not running") {
        KvServer server{srv_config, chaindata, state_change_source.get()};
        server.shutdown();
        server.shutdown();
    }

    SECTION("KvServer::shutdown OK: shutdown running server") {
        KvServer server{srv_config, chaindata, state_change_source.get()};
        server.build_and_start();
        server.shutdown();
        server.join();
    }

    SECTION("KvServer::shutdown OK: shutdown twice running server") {
        KvServer server{srv_config, chaindata, state_change_source.get()};
        server.build_and_start();
        server.shutdown();
        server.shutdown();
        server.join();
    }

    SECTION("KvServer::shutdown OK: shutdown running server again after join") {
        KvServer server{srv_config, chaindata, state_change_source.get()};
        server.build_and_start();
        server.shutdown();
        server.join();
        server.shutdown();
    }

    SECTION("KvServer::join OK: shutdown joined server") {
        KvServer server{srv_config, chaindata, state_change_source.get()};
        server.build_and_start();
        std::thread server_thread{[&server]() { server.join(); }};
        server.shutdown();
        server_thread.join();
    }

    SECTION("KvServer::join OK: shutdown joined server and join again") {
        KvServer server{srv_config, chaindata, state_change_source.get()};
        server.build_and_start();
        std::thread server_thread{[&server]() { server.join(); }};
        server.shutdown();
        server_thread.join();
        server.join();  // cannot move before server_thread.join() due to data race in boost::asio::detail::posix_thread
    }
}

TEST_CASE_METHOD(KvEnd2EndTest, "KvServer E2E: KV", "[silkworm][node][rpc]") {
    SECTION("Version: return KV version") {
        types::VersionReply response;
        const auto status = kv_client->version(&response);
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
        const auto status = kv_client->tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == ::grpc::StatusCode::INVALID_ARGUMENT);
        CHECK(absl::StrContains(status.error_message(), "unknown bucket"));
        CHECK(responses.size() == 1);
        CHECK(responses[0].tx_id() != 0);
    }

    SECTION("Tx KO: invalid table name") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name("NonexistentTable");
        std::vector<remote::Cursor> requests{open};
        std::vector<remote::Pair> responses;
        const auto status = kv_client->tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == ::grpc::StatusCode::INVALID_ARGUMENT);
        CHECK(absl::StrContains(status.error_message(), "unknown bucket"));
        CHECK(responses.size() == 1);
        CHECK(responses[0].tx_id() != 0);
    }

    SECTION("Tx KO: missing operation") {
        remote::Cursor open;
        open.set_bucket_name(kTestMap.name);
        std::vector<remote::Cursor> requests{open};
        std::vector<remote::Pair> responses;
        const auto status = kv_client->tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == ::grpc::StatusCode::INVALID_ARGUMENT);
        CHECK(absl::StrContains(status.error_message(), "unknown cursor"));
        CHECK(responses.size() == 1);
        CHECK(responses[0].tx_id() != 0);
    }

    SECTION("Tx OK: just start then finish") {
        std::vector<remote::Cursor> requests{};
        std::vector<remote::Pair> responses;
        const auto status = kv_client->tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 1);
        CHECK(responses[0].tx_id() != 0);
    }

    SECTION("Tx OK: cursor opened") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
        std::vector<remote::Cursor> requests{open};
        std::vector<remote::Pair> responses;
        const auto status = kv_client->tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 2);
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
    }

    SECTION("Tx OK: cursor dup_sort opened") {
        remote::Cursor open_dup_sort;
        open_dup_sort.set_op(remote::Op::OPEN_DUP_SORT);
        open_dup_sort.set_bucket_name(kTestMultiMap.name);
        std::vector<remote::Cursor> requests{open_dup_sort};
        std::vector<remote::Pair> responses;
        const auto status = kv_client->tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 2);
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
    }

    SECTION("Tx OK: cursor opened then closed") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);
        std::vector<remote::Cursor> requests{open, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client->tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 3);
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].cursor_id() == 0);
    }

    SECTION("Tx OK: cursor dup_sort opened then closed") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN_DUP_SORT);
        open.set_bucket_name(kTestMultiMap.name);
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(0);
        std::vector<remote::Cursor> requests{open, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client->tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 3);
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].cursor_id() == 0);
    }

    SECTION("Tx KO: cursor opened then unknown") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        close.set_cursor(12345);
        std::vector<remote::Cursor> requests{open, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client->tx(requests, responses);
        CHECK(!status.ok());
        CHECK(status.error_code() == ::grpc::StatusCode::INVALID_ARGUMENT);
        CHECK(absl::StrContains(status.error_message(), "unknown cursor"));
        CHECK(responses.size() == 2);
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
    }

    SECTION("Tx OK: one FIRST operation on empty table gives empty result") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(0);
        std::vector<remote::Cursor> requests{open, first};
        std::vector<remote::Pair> responses;
        const auto status = kv_client->tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 3);
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[1].k().empty());
        CHECK(responses[1].v().empty());
    }

    SECTION("Tx KO: one NEXT operation on empty table gives empty result") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
        remote::Cursor next;
        next.set_op(remote::Op::NEXT);
        next.set_cursor(0);
        std::vector<remote::Cursor> requests{open, next};
        std::vector<remote::Pair> responses;
        const auto status = kv_client->tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 3);
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[1].k().empty());
        CHECK(responses[1].v().empty());
    }

    SECTION("StateChanges OK: receive streamed state changes") {
        static constexpr uint64_t kTestPendingBaseFee{10'000};
        static constexpr uint64_t kTestGasLimit{10'000'000};
        auto* state_change_source = state_change_collection.get();

        ThreadedKvClient threaded_kv_client;

        // Start StateChanges server-streaming call and consume incoming messages on dedicated thread
        threaded_kv_client.start_and_consume_statechanges(*kv_client);

        // Keep publishing state changes using the Catch2 thread until at least one has been received
        BlockNum block_num{0};
        bool publishing{true};
        while (publishing) {
            state_change_source->start_new_batch(++block_num, kEmptyHash, std::vector<Bytes>{}, /*unwind=*/false);
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
        auto* state_change_source = state_change_collection.get();

        ThreadedKvClient threaded_kv_client1, threaded_kv_client2;

        // Start StateChanges server-streaming call and consume incoming messages on dedicated thread
        threaded_kv_client1.start_and_consume_statechanges(*kv_client);
        threaded_kv_client2.start_and_consume_statechanges(*kv_client);

        // Keep publishing state changes using the Catch2 thread until at least one has been received
        BlockNum block_num{0};
        bool publishing{true};
        while (publishing) {
            state_change_source->start_new_batch(++block_num, kEmptyHash, {}, /*unwind=*/false);
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
        auto* state_change_source = state_change_collection.get();

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
        ::grpc::ClientContext context1;
        remote::StateChangeRequest request1;
        auto subscribe_reply_reader1 = kv_client->statechanges_start(&context1, request1);

        // Wait for token reset condition to happen
        std::unique_lock token_reset_lock{token_reset_mutex};
        token_reset_condition.wait(token_reset_lock, [&] { return token_reset; });

        // Start another StateChanges server-streaming call and check it fails
        ::grpc::ClientContext context2;
        remote::StateChangeRequest request2;
        auto subscribe_reply_reader2 = kv_client->statechanges_start(&context2, request2);

        const auto status2 = subscribe_reply_reader2->Finish();
        CHECK(!status2.ok());
        CHECK(status2.error_code() == ::grpc::StatusCode::ALREADY_EXISTS);
        CHECK(absl::StrContains(status2.error_message(), "assigned consumer token already in use"));

        // Close the server-side RPC stream and check first call completes successfully
        state_change_source->close();

        const auto status1 = subscribe_reply_reader1->Finish();
        CHECK(status1.ok());
    }

    SECTION("Snapshots: return snapshot files") {
        remote::SnapshotsRequest request;
        remote::SnapshotsReply response;
        const auto status = kv_client->snapshots(request, &response);
        CHECK(status.ok());
    }

    SECTION("HistorySeek: return value in target history") {
        remote::HistorySeekReq request;
        remote::HistorySeekReply response;
        const auto status = kv_client->history_seek(request, &response);
        CHECK(status.ok());
    }

    SECTION("GetLatest: return value in target domain") {
        remote::GetLatestReq request;
        remote::GetLatestReply response;
        const auto status = kv_client->get_latest(request, &response);
        CHECK(status.ok());
    }

    SECTION("IndexRange: return value in target index range") {
        remote::IndexRangeReq request;
        remote::IndexRangeReply response;
        const auto status = kv_client->index_range(request, &response);
        CHECK(status.ok());
    }

    SECTION("HistoryRange: return value in target history range") {
        remote::HistoryRangeReq request;
        remote::Pairs response;
        const auto status = kv_client->history_range(request, &response);
        CHECK(status.ok());
    }

    SECTION("RangeAsOf: return value in target domain range") {
        remote::RangeAsOfReq request;
        remote::Pairs response;
        const auto status = kv_client->range_as_of(request, &response);
        CHECK(status.ok());
    }
}

#ifndef _WIN32
TEST_CASE("KvServer E2E: trigger server-side write error", "[silkworm][node][rpc]") {
    {
        const uint32_t num_txs{1000};
        KvEnd2EndTest test;
        test.fill_tables();
        auto kv_client = *test.kv_client;

        // Start many Tx calls w/o reading responses after writing requests.
        for (uint32_t i{0}; i < num_txs; ++i) {
            ::grpc::ClientContext context;
            auto tx_stream = kv_client.tx_start(&context);
            remote::Pair response;
            CHECK(tx_stream->Read(&response));
            CHECK(response.tx_id() != 0);
            remote::Cursor open;
            open.set_op(remote::Op::OPEN);
            open.set_bucket_name(kTestMap.name);
            CHECK(tx_stream->Write(open));
        }
    }
    // Server-side life cycle of Tx calls must be OK.
}
#endif  // _WIN32

TEST_CASE("KvServer E2E: Tx max simultaneous readers exceeded", "[silkworm][node][rpc]") {
    // This check can be improved in Catch2 version 3.3.0 where SKIP is available
    if (os::max_file_descriptors() < 1024) {
        bool ok = os::set_max_file_descriptors(1024);
        if (!ok) {
            FAIL("insufficient number of process file descriptors, increase to 1024 has failed");
        }
    }

    KvEnd2EndTest test;
    test.fill_tables();
    auto kv_client = *test.kv_client;

    // Start and keep open as many Tx calls as the maximum number of readers.
    std::vector<std::unique_ptr<::grpc::ClientContext>> client_contexts;
    std::vector<TxStreamPtr> tx_streams;
    for (uint32_t i{0}; i < test.database_env.max_readers(); ++i) {
        auto& context = client_contexts.emplace_back(std::make_unique<::grpc::ClientContext>());
        auto tx_stream = kv_client.tx_start(context.get());
        // You must read at least the first unsolicited incoming message (TxID announcement).
        remote::Pair response;
        REQUIRE(tx_stream->Read(&response));
        REQUIRE(response.tx_id() != 0);
        tx_streams.push_back(std::move(tx_stream));
    }

    // Now trying to start another Tx call will exceed the maximum number of readers.
    ::grpc::ClientContext context;
    const auto failing_tx_stream = kv_client.tx_start(&context);
    remote::Pair response;
    REQUIRE(!failing_tx_stream->Read(&response));  // Tx RPC immediately fails for exhaustion, no TxID announcement
    auto failing_tx_status = failing_tx_stream->Finish();
    CHECK(!failing_tx_status.ok());
    CHECK(failing_tx_status.error_code() == ::grpc::StatusCode::RESOURCE_EXHAUSTED);
    CHECK(absl::StrContains(failing_tx_status.error_message(), "start tx failed"));

    // Dispose all the opened Tx calls.
    for (const auto& tx_stream : tx_streams) {
        REQUIRE(tx_stream->WritesDone());
        auto status = tx_stream->Finish();
        REQUIRE(status.ok());
    }
}

TEST_CASE("KvServer E2E: Tx max opened cursors exceeded", "[silkworm][node][rpc]") {
    KvEnd2EndTest test;
    test.fill_tables();
    auto kv_client = *test.kv_client;

    ::grpc::ClientContext context;
    const auto tx_stream = kv_client.tx_start(&context);
    // You must read at least the first unsolicited incoming message (TxID announcement).
    remote::Pair response;
    REQUIRE(tx_stream->Read(&response));
    REQUIRE(response.tx_id() != 0);
    response.clear_tx_id();
    // Open as many cursors as possible expecting successful result.
    for (uint32_t i{0}; i < kMaxTxCursors; ++i) {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
        REQUIRE(tx_stream->Write(open));
        response.clear_cursor_id();
        REQUIRE(tx_stream->Read(&response));
        REQUIRE(response.cursor_id() != 0);
    }
    // Try to open one more and get failure from server-side on the stream.
    remote::Cursor open;
    open.set_op(remote::Op::OPEN);
    open.set_bucket_name(kTestMap.name);
    REQUIRE(tx_stream->Write(open));
    response.clear_cursor_id();
    REQUIRE(!tx_stream->Read(&response));
    REQUIRE(response.cursor_id() == 0);
    // Half-close the stream and complete the call checking expected failure.
    REQUIRE(tx_stream->WritesDone());
    auto status = tx_stream->Finish();
    CHECK(!status.ok());
    CHECK(status.error_code() == ::grpc::StatusCode::RESOURCE_EXHAUSTED);
    CHECK(absl::StrContains(status.error_message(), "maximum cursors per txn"));
}

class TxIdleTimeoutGuard {
  public:
    explicit TxIdleTimeoutGuard(uint8_t t) { TxCall::set_max_idle_duration(std::chrono::milliseconds{t}); }
    ~TxIdleTimeoutGuard() { TxCall::set_max_idle_duration(rpc::server::kDefaultMaxIdleDuration); }
};

TEST_CASE("KvServer E2E: bidirectional idle timeout", "[silkworm][node][rpc]") {
    TxIdleTimeoutGuard timeout_guard{100};
    KvEnd2EndTest test;
    test.fill_tables();
    auto kv_client = *test.kv_client;

    // This commented test *blocks* starting from gRPC 1.44.0-p0 (works using gRPC 1.38.0-p0)
    // The reason could be that according to gRPC API spec this is kind of API misuse: it is
    // *appropriate* to call Finish only after all incoming messages have been read (not the
    // case here, missing tx ID announcement read) *and* no outgoing messages need to be sent.
    /*SECTION("Tx KO: immediate finish", "[.]") {
        ::grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        auto status = tx_reader_writer->Finish();
        CHECK(!status.ok());
        CHECK(status.error_code() == ::grpc::StatusCode::DEADLINE_EXCEEDED);
        CHECK(absl::StrContains(status.error_message(), "call idle, no incoming request"));
    }*/

    SECTION("Tx KO: finish after first read (w/o WritesDone)") {
        ::grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.tx_id() != 0);
        auto status = tx_reader_writer->Finish();
        CHECK(!status.ok());
        CHECK(status.error_code() == ::grpc::StatusCode::DEADLINE_EXCEEDED);
        CHECK(absl::StrContains(status.error_message(), "no incoming request"));
    }

    SECTION("Tx KO: finish after first read and one write/read (w/o WritesDone)") {
        ::grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.tx_id() != 0);
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
        CHECK(tx_reader_writer->Write(open));
        response.clear_tx_id();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.cursor_id() != 0);
        auto status = tx_reader_writer->Finish();
        CHECK(!status.ok());
        CHECK(status.error_code() == ::grpc::StatusCode::DEADLINE_EXCEEDED);
        CHECK(absl::StrContains(status.error_message(), "no incoming request"));
    }
}

TEST_CASE("KvServer E2E: Tx cursor valid operations", "[silkworm][node][rpc]") {
    KvEnd2EndTest test;
    test.fill_tables();
    auto kv_client = *test.kv_client;

    SECTION("Tx OK: one FIRST operation") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: two FIRST operations") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].k() == "AA");
        CHECK(responses[3].v() == "00");
        CHECK(responses[4].cursor_id() == 0);
    }

    SECTION("Tx OK: one LAST operation") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: two LAST operations") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].k() == "BB");
        CHECK(responses[3].v() == "11");
        CHECK(responses[4].cursor_id() == 0);
    }

    SECTION("Tx OK: one NEXT operation") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: two NEXT operations") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].k() == "BB");
        CHECK(responses[3].v() == "11");
        CHECK(responses[4].cursor_id() == 0);
    }

    SECTION("Tx OK: two NEXT operations using different cursors") {
        remote::Cursor open1;
        open1.set_op(remote::Op::OPEN);
        open1.set_bucket_name(kTestMap.name);
        remote::Cursor next1;
        next1.set_op(remote::Op::NEXT);
        next1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close1;
        close1.set_op(remote::Op::CLOSE);
        close1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor open2;
        open2.set_op(remote::Op::OPEN);
        open2.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursor_id() == 0);
        CHECK(responses[4].cursor_id() != 0);
        CHECK(responses[5].k() == "AA");
        CHECK(responses[5].v() == "00");
        CHECK(responses[6].cursor_id() == 0);
    }

    SECTION("Tx OK: one PREV operation") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: two PREV operations") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].k() == "AA");
        CHECK(responses[3].v() == "00");
        CHECK(responses[4].cursor_id() == 0);
    }

    SECTION("Tx OK: two PREV operations using different cursors") {
        remote::Cursor open1;
        open1.set_op(remote::Op::OPEN);
        open1.set_bucket_name(kTestMap.name);
        remote::Cursor prev1;
        prev1.set_op(remote::Op::PREV);
        prev1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor close1;
        close1.set_op(remote::Op::CLOSE);
        close1.set_cursor(0);  // automatically assigned by KvClient::tx
        remote::Cursor open2;
        open2.set_op(remote::Op::OPEN);
        open2.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].cursor_id() == 0);
        CHECK(responses[4].cursor_id() != 0);
        CHECK(responses[5].k() == "BB");
        CHECK(responses[5].v() == "11");
        CHECK(responses[6].cursor_id() == 0);
    }

    SECTION("Tx OK: FIRST + CURRENT operations on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].k() == "AA");
        CHECK(responses[3].v() == "00");
        CHECK(responses[4].cursor_id() == 0);
    }

    SECTION("Tx OK: LAST + CURRENT operations on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].k() == "BB");
        CHECK(responses[3].v() == "22");
        CHECK(responses[4].cursor_id() == 0);
    }

    SECTION("Tx OK: FIRST + FIRST_DUP operations on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].k().empty());
        CHECK(responses[3].v() == "00");
        CHECK(responses[4].cursor_id() == 0);
    }

    SECTION("Tx OK: LAST + FIRST_DUP operations on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].k().empty());
        CHECK(responses[3].v() == "22");
        CHECK(responses[4].cursor_id() == 0);
    }

    SECTION("Tx OK: one FIRST + two NEXT_DUP operations on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].k() == "AA");
        CHECK(responses[3].v() == "11");
        CHECK(responses[4].k() == "AA");
        CHECK(responses[4].v() == "22");
        CHECK(responses[5].cursor_id() == 0);
    }

    SECTION("Tx OK: NEXT_DUP operation on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one PREV_DUP operation on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one NEXT_DUP operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one PREV_DUP operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one FIRST + one LAST_DUP operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].k().empty());
        CHECK(responses[3].v() == "22");
        CHECK(responses[4].cursor_id() == 0);
    }

    SECTION("Tx OK: one LAST + one LAST_DUP operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].k().empty());
        CHECK(responses[3].v() == "22");
        CHECK(responses[4].cursor_id() == 0);
    }

    SECTION("Tx OK: one NEXT_NO_DUP operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one PREV_NO_DUP operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: SEEK operation w/o key on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: SEEK operation w/ existent key on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: SEEK operation w/ unexisting key on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v().empty());
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: SEEK_EXACT operation w/o key on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v().empty());
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: SEEK_EXACT operation w/ existent key on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "BB");
        CHECK(responses[2].v() == "11");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: SEEK_EXACT operation w/ nonexistent key on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v().empty());
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one SEEK_BOTH w/o key operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v().empty());
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one SEEK_BOTH w/ nonexistent key operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v().empty());
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one SEEK_BOTH w/ existent key operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v() == "00");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one SEEK_BOTH w/ existent key+value operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one SEEK_BOTH_EXACT w/o key operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v().empty());
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one SEEK_BOTH_EXACT w/ nonexistent key operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v().empty());
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one SEEK_BOTH_EXACT w/ existent key operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k().empty());
        CHECK(responses[2].v().empty());
        CHECK(responses[3].cursor_id() == 0);
    }

    SECTION("Tx OK: one SEEK_BOTH_EXACT w/ existent key+value operation on multi-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
        CHECK(responses[2].k() == "AA");
        CHECK(responses[2].v() == "22");
        CHECK(responses[3].cursor_id() == 0);
    }
}

TEST_CASE("KvServer E2E: Tx cursor invalid operations", "[silkworm][node][rpc]") {
    KvEnd2EndTest test;
    test.fill_tables();
    auto kv_client = *test.kv_client;

    SECTION("Tx KO: CURRENT operation") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(status.error_code() == ::grpc::StatusCode::INTERNAL);
        CHECK(absl::StrContains(status.error_message(), "exception: MDBX_ENODATA"));
        CHECK(responses.size() == 2);
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
    }

    SECTION("Tx KO: FIRST_DUP operation on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(status.error_code() == ::grpc::StatusCode::INTERNAL);
        CHECK(absl::StrContains(status.error_message(), "exception: MDBX_INCOMPATIBLE"));
        CHECK(responses.size() == 3);
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
    }

    SECTION("Tx KO: LAST_DUP operation on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(status.error_code() == ::grpc::StatusCode::INTERNAL);
        CHECK(absl::StrContains(status.error_message(), "exception: MDBX_INCOMPATIBLE"));
        CHECK(responses.size() == 3);
        CHECK(responses[0].tx_id() != 0);
        CHECK(responses[1].cursor_id() != 0);
    }

    SECTION("Tx KO: FIRST_DUP operation w/o positioned key") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(status.error_code() == ::grpc::StatusCode::INTERNAL);
        CHECK(absl::StrContains(status.error_message(), "exception: mdbx"));
        CHECK(responses.size() == 2);
        CHECK(responses[0].tx_id() != 0);
    }

    SECTION("Tx KO: LAST_DUP operation w/o positioned key") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
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
        CHECK(status.error_code() == ::grpc::StatusCode::INTERNAL);
        CHECK(absl::StrContains(status.error_message(), "exception: mdbx"));
        CHECK(responses.size() == 2);
        CHECK(responses[0].tx_id() != 0);
    }

    SECTION("Tx KO: SEEK_BOTH operation on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(status.error_code() == ::grpc::StatusCode::INTERNAL);
        CHECK(absl::StrContains(status.error_message(), "MDBX_INCOMPATIBLE"));
        CHECK(responses.size() == 2);
        CHECK(responses[0].tx_id() != 0);
    }

    SECTION("Tx KO: SEEK_BOTH_EXACT operation on single-value table") {
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
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
        CHECK(status.error_code() == ::grpc::StatusCode::INTERNAL);
        CHECK(absl::StrContains(status.error_message(), "MDBX_INCOMPATIBLE"));
        CHECK(responses.size() == 2);
        CHECK(responses[0].tx_id() != 0);
    }
}

class TxMaxTimeToLiveGuard {
  public:
    explicit TxMaxTimeToLiveGuard(std::chrono::milliseconds t) { TxCall::set_max_ttl_duration(t); }
    ~TxMaxTimeToLiveGuard() { TxCall::set_max_ttl_duration(kMaxTxDuration); }
};

TEST_CASE("KvServer E2E: bidirectional max TTL duration", "[silkworm][node][rpc]") {
    KvEnd2EndTest test;
    test.fill_tables();
    auto kv_client = *test.kv_client;
    static constexpr std::chrono::milliseconds kCustomMaxTimeToLive = 1000ms;
    TxMaxTimeToLiveGuard ttl_guard{kCustomMaxTimeToLive};

    SECTION("Tx: cursor NEXT ops across renew are consecutive") {
        ::grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.tx_id() != 0);
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
        CHECK(tx_reader_writer->Write(open));
        response.clear_tx_id();
        CHECK(tx_reader_writer->Read(&response));
        const auto cursor_id = response.cursor_id();
        CHECK(cursor_id != 0);
        remote::Cursor next1;
        next1.set_op(remote::Op::NEXT);
        next1.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next1));
        response.clear_cursor_id();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "00");
        std::this_thread::sleep_for(kCustomMaxTimeToLive);
        remote::Cursor next2;
        next2.set_op(remote::Op::NEXT);
        next2.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next2));
        response.clear_cursor_id();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "BB");
        CHECK(response.v() == "11");
        tx_reader_writer->WritesDone();
        auto status = tx_reader_writer->Finish();
        CHECK(status.ok());
    }

    SECTION("Tx: cursor NEXT_DUP ops across renew are consecutive") {
        ::grpc::ClientContext context;
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.tx_id() != 0);
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
        CHECK(tx_reader_writer->Write(open));
        response.clear_tx_id();
        CHECK(tx_reader_writer->Read(&response));
        const auto cursor_id = response.cursor_id();
        CHECK(cursor_id != 0);
        remote::Cursor next_dup1;
        next_dup1.set_op(remote::Op::NEXT_DUP);
        next_dup1.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next_dup1));
        response.clear_cursor_id();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "00");
        std::this_thread::sleep_for(kCustomMaxTimeToLive);
        remote::Cursor next_dup2;
        next_dup2.set_op(remote::Op::NEXT_DUP);
        next_dup2.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next_dup2));
        response.clear_cursor_id();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "11");
        tx_reader_writer->WritesDone();
        auto status = tx_reader_writer->Finish();
        CHECK(status.ok());
    }

#ifndef _WIN32
    SECTION("Tx: cursor NEXT op after renew sees changes") {
        ::grpc::ClientContext context;
        // Start Tx RPC and open one cursor for TestMap table
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.tx_id() != 0);
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMap.name);
        CHECK(tx_reader_writer->Write(open));
        response.clear_tx_id();
        CHECK(tx_reader_writer->Read(&response));
        const auto cursor_id = response.cursor_id();
        CHECK(cursor_id != 0);
        // Change database content *after* Tx RPC has been opened
        test.alter_tables();
        // Tx RPC opened *before* database changes won't see them
        remote::Cursor next1;
        next1.set_op(remote::Op::NEXT);
        next1.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next1));
        response.clear_cursor_id();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "00");
        CHECK(tx_reader_writer->Write(next1));
        response.clear_k();
        response.clear_v();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "BB");
        CHECK(response.v() == "11");
        CHECK(tx_reader_writer->Write(next1));
        response.clear_k();
        response.clear_v();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k().empty());
        CHECK(response.v().empty());
        // Let the max TTL timer expire causing server-side tx renewal
        std::this_thread::sleep_for(kCustomMaxTimeToLive);
        // Now the already existing cursor (i.e. same cursor_id) can see the changes
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(first));
        response.clear_cursor_id();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "00");
        remote::Cursor next2;
        next2.set_op(remote::Op::NEXT);
        next2.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next2));
        response.clear_k();
        response.clear_v();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "BB");
        CHECK(response.v() == "11");
        CHECK(tx_reader_writer->Write(next2));
        response.clear_k();
        response.clear_v();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "CC");
        CHECK(response.v() == "22");
        tx_reader_writer->WritesDone();
        auto status = tx_reader_writer->Finish();
        CHECK(status.ok());
    }

    SECTION("Tx: cursor NEXT_DUP op after renew sees changes") {
        ::grpc::ClientContext context;
        // Start Tx RPC and open one cursor for TestMultiMap table
        const auto tx_reader_writer = kv_client.tx_start(&context);
        remote::Pair response;
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.tx_id() != 0);
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucket_name(kTestMultiMap.name);
        CHECK(tx_reader_writer->Write(open));
        response.clear_tx_id();
        CHECK(tx_reader_writer->Read(&response));
        const auto cursor_id = response.cursor_id();
        CHECK(cursor_id != 0);
        // Change database content *after* Tx RPC has been opened
        test.alter_tables();
        // Tx RPC opened *before* database changes won't see them
        remote::Cursor next_dup;
        next_dup.set_op(remote::Op::NEXT_DUP);
        next_dup.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(next_dup));
        response.clear_cursor_id();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "00");
        CHECK(tx_reader_writer->Write(next_dup));
        response.clear_k();
        response.clear_v();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "11");
        CHECK(tx_reader_writer->Write(next_dup));
        response.clear_k();
        response.clear_v();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "22");
        CHECK(tx_reader_writer->Write(next_dup));
        response.clear_k();
        response.clear_v();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k().empty());
        CHECK(response.v().empty());
        // Let the max TTL timer expire causing server-side tx renewal
        std::this_thread::sleep_for(kCustomMaxTimeToLive);
        // Now the already existing cursor (i.e. same cursor_id) can see the changes
        remote::Cursor first;
        first.set_op(remote::Op::FIRST);
        first.set_cursor(cursor_id);
        CHECK(tx_reader_writer->Write(first));
        response.clear_cursor_id();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "00");
        CHECK(tx_reader_writer->Write(next_dup));
        response.clear_k();
        response.clear_v();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "11");
        CHECK(tx_reader_writer->Write(next_dup));
        response.clear_k();
        response.clear_v();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "22");
        CHECK(tx_reader_writer->Write(next_dup));
        response.clear_k();
        response.clear_v();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k() == "AA");
        CHECK(response.v() == "33");
        CHECK(tx_reader_writer->Write(next_dup));
        response.clear_k();
        response.clear_v();
        CHECK(tx_reader_writer->Read(&response));
        CHECK(response.k().empty());
        CHECK(response.v().empty());
        tx_reader_writer->WritesDone();
        auto status = tx_reader_writer->Finish();
        CHECK(status.ok());
    }

#endif  // _WIN32
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::db::kv::grpc::server
