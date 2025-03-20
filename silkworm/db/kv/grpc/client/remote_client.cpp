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

#include "remote_client.hpp"

#include <agrpc/client_rpc.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <grpcpp/grpcpp.h>
#include <gsl/util>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/sleep.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/grpc/client/reconnect.hpp>
#include <silkworm/infra/grpc/common/util.hpp>

#include "endpoint/state_change.hpp"
#include "remote_transaction.hpp"

namespace silkworm::db::kv::grpc::client {

namespace proto = ::remote;
using Stub = proto::KV::StubInterface;

class RemoteClientImpl final : public api::Service {
  public:
    RemoteClientImpl(const rpc::ChannelFactory& create_channel,
                     agrpc::GrpcContext& grpc_context,
                     api::StateCache* state_cache,
                     chain::Providers providers,
                     rpc::DisconnectHook on_disconnect)
        : channel_{create_channel()},
          stub_{proto::KV::NewStub(channel_)},
          grpc_context_{grpc_context},
          state_cache_{state_cache},
          providers_{std::move(providers)},
          on_disconnect_{std::move(on_disconnect)} {}
    RemoteClientImpl(std::unique_ptr<Stub> stub,
                     agrpc::GrpcContext& grpc_context,
                     api::StateCache* state_cache,
                     chain::Providers providers,
                     rpc::DisconnectHook on_disconnect)
        : stub_{std::move(stub)},
          grpc_context_{grpc_context},
          state_cache_{state_cache},
          providers_{std::move(providers)},
          on_disconnect_{std::move(on_disconnect)} {}

    ~RemoteClientImpl() override = default;

    RemoteClientImpl(const RemoteClientImpl&) = delete;
    RemoteClientImpl& operator=(const RemoteClientImpl&) = delete;

    // rpc Version(google.protobuf.Empty) returns (types.VersionReply);
    Task<api::Version> version() override {
        co_return api::kCurrentVersion;
    }

    // rpc Tx(stream Cursor) returns (stream Pair);
    Task<std::unique_ptr<api::Transaction>> begin_transaction() override {
        auto tx = std::make_unique<RemoteTransaction>(*stub_, grpc_context_, state_cache_, providers_);
        co_await tx->open();
        co_return tx;
    }

    // rpc StateChanges(StateChangeRequest) returns (stream StateChangeBatch);
    Task<void> state_changes(const api::StateChangeOptions& options, api::StateChangeConsumer consumer) override {
        using StateChangesRpc =
            boost::asio::use_awaitable_t<>::as_default_on_t<agrpc::ClientRPC<&Stub::PrepareAsyncStateChanges>>;

        size_t attempt = 0;
        while (true) {
            SILK_TRACE << "State changes RPC attempt=" << attempt;
            try {
                proto::StateChangeRequest request = request_from_state_change_options(options);

                auto rpc = std::make_shared<StateChangesRpc>(grpc_context_);
                if (options.cancellation_token) {
                    const bool cancelled = options.cancellation_token->assign([rpc](boost::asio::cancellation_type /*type*/) {
                        rpc->cancel();
                    });
                    if (cancelled) {
                        SILK_TRACE << "State changes RPC cancelled while retrying ptr=" << rpc.get();
                        throw rpc::GrpcStatusError{::grpc::Status::CANCELLED};
                    }
                    SILK_TRACE << "State changes RPC cancellation handler registered ptr=" << rpc.get();
                }
                if (!co_await rpc->start(*stub_, request)) {
                    ::grpc::Status status = co_await rpc->finish();
                    SILK_TRACE << "State changes RPC start failed status=" << status;
                    throw rpc::GrpcStatusError{std::move(status)};
                }
                proto::StateChangeBatch batch;
                while (co_await rpc->read(batch)) {
                    co_await consumer(state_change_set_from_batch(batch));
                }

                ::grpc::Status status = co_await rpc->finish();
                if (!status.ok()) {
                    SILK_TRACE << "State changes RPC finish failed status=" << status;
                    throw rpc::GrpcStatusError{std::move(status)};
                }
                co_return;
            } catch (const rpc::GrpcStatusError& gse) {
                const auto error_code = gse.status().error_code();
                if (error_code == ::grpc::StatusCode::ABORTED || error_code == ::grpc::StatusCode::CANCELLED) {
                    co_return;
                }
                SILK_TRACE << "State changes RPC error occurred status=" << gse.status();
            }
            // Next lines must be here even if logically they belong to catch clause (no co_await within catch block)
            const auto timeout = rpc::backoff_timeout(attempt++, min_backoff_timeout_.count(), max_backoff_timeout_.count());
            co_await sleep(std::chrono::milliseconds(timeout));
        }
    }

    void set_min_backoff_timeout(const std::chrono::milliseconds& min_backoff_timeout) {
        min_backoff_timeout_ = min_backoff_timeout;
    }

    void set_max_backoff_timeout(const std::chrono::milliseconds& max_backoff_timeout) {
        max_backoff_timeout_ = max_backoff_timeout;
    }

  private:
    std::shared_ptr<::grpc::Channel> channel_;
    std::unique_ptr<Stub> stub_;
    agrpc::GrpcContext& grpc_context_;
    api::StateCache* state_cache_;
    chain::Providers providers_;
    rpc::DisconnectHook on_disconnect_;
    std::chrono::milliseconds min_backoff_timeout_{rpc::kDefaultMinBackoffReconnectTimeout};
    std::chrono::milliseconds max_backoff_timeout_{rpc::kDefaultMaxBackoffReconnectTimeout};
};

RemoteClient::RemoteClient(const rpc::ChannelFactory& create_channel,
                           agrpc::GrpcContext& grpc_context,
                           api::StateCache* state_cache,
                           chain::Providers providers,
                           rpc::DisconnectHook on_disconnect)
    : p_impl_{std::make_shared<RemoteClientImpl>(create_channel,
                                                 grpc_context,
                                                 state_cache,
                                                 std::move(providers),
                                                 std::move(on_disconnect))} {}

RemoteClient::RemoteClient(std::unique_ptr<Stub> stub,
                           agrpc::GrpcContext& grpc_context,
                           api::StateCache* state_cache,
                           chain::Providers providers,
                           rpc::DisconnectHook on_disconnect)
    : p_impl_{std::make_shared<RemoteClientImpl>(std::move(stub),
                                                 grpc_context,
                                                 state_cache,
                                                 std::move(providers),
                                                 std::move(on_disconnect))} {}

// Must be here (not in header) because RemoteClientImpl size is necessary for std::unique_ptr in PIMPL idiom
RemoteClient::~RemoteClient() = default;

std::shared_ptr<api::Service> RemoteClient::service() {
    return p_impl_;
}

void RemoteClient::set_min_backoff_timeout(const std::chrono::milliseconds& min_timeout) {
    p_impl_->set_min_backoff_timeout(min_timeout);
}

void RemoteClient::set_max_backoff_timeout(const std::chrono::milliseconds& max_timeout) {
    p_impl_->set_max_backoff_timeout(max_timeout);
}

}  // namespace silkworm::db::kv::grpc::client
