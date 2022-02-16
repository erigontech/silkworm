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

#ifndef SILKWORM_RPC_CALL_HPP_
#define SILKWORM_RPC_CALL_HPP_

#include <atomic>
#include <functional>

#include <grpcpp/grpcpp.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/completion_tag.hpp>

namespace silkworm::rpc {

//! This represents the generic gRPC call composed by a sequence of bidirectional operations.
class BaseRpc {
  public:
    static int32_t instance_count() { return instance_count_; }

    BaseRpc() : op_count_(0), done_(false) {
        instance_count_++;
        SILK_TRACE << "BaseRpc::BaseRpc [" << this << "] instances: " << instance_count_;
    }

    virtual ~BaseRpc() {
        instance_count_--;
        SILK_TRACE << "BaseRpc::~BaseRpc [" << this << "] instances: " << instance_count_;
    }

    /// Tag processor for the DONE event in this RPC coming from gRPC framework.
    void process_done(bool ok) {
        SILK_TRACE << "BaseRpc::on_done START ok: " << ok << " done_: " << done_ << " op_count_: " << op_count_;
        done_ = true;
        if (op_count_ == 0) {
            cleanup();
        }
        SILK_TRACE << "BaseRpc::on_done END ok: " << ok << " op_count_: " << op_count_;
    }

  protected:
    /// Hook to signal this RPC is *really* done: each subclass shall override to implement its own cleanup.
    virtual void cleanup() = 0;

    //! The 4 different types of bidirectional operations composing a RPC.
    /// Some operations may occur multiple times during a single RPC lifetime.
    enum class OperationType {
        kRequest,
        kRead,
        kWrite,
        kFinish
    };

    /// Callback to handle the start of the specified async operation.
    void handle_started(OperationType opType) {
        ++op_count_;
        SILK_TRACE << "BaseRpc::handle_started opType: " << static_cast<int>(opType) << " op_count_: " << op_count_;
    }

    /// Callback to handle the end of the specified async operation.
    /// \return true if the RPC processing should keep going, false otherwise
    bool handle_completed(OperationType opType) {
        --op_count_;
        SILK_TRACE << "BaseRpc::handle_completed opType: " << static_cast<int>(opType) << " op_count_: " << op_count_;

        if (op_count_ == 0 && done_) {
            // No async operations pending and gRPC library already notified that this RPC is done => cleanup.
            cleanup();
            return false;
        }

        return true;
    }

    /// Used to access the options and current status of the RPC.
    grpc::ServerContext context_;

    /// Keep track of the total outstanding RPC calls (intentionally signed to spot underflows).
    inline static std::atomic_int64_t instance_count_ = 0;

  private:
    /// This counts the number of pending operations in this RPC.
    /// \warning It is used to detect when the RPC is really done in some corner cases (e.g. client abruptly exits).
    uint32_t op_count_;

    /// This flag indicates if DONE tag processor has been called or not.
    /// \warning It is used to handle some corner cases when the completion queue dispatches tags in reverse order
    /// (e.g. client abruptly exits).
    bool done_;
};

//! Contains the callback functions used to customize the RPC handling.
/// Any concrete RPC (unary/mono streaming/bi streaming) shall specialize RpcHandlers because each of them will use
/// a different response writer to call the gRPC library.
/// \warning Note that in gRPC async model an application must explicitly ask the gRPC server to start handling an
/// incoming RPC on a particular service: that's why createRpc exists.
template <typename Service, typename Request, typename Response, typename Rpc>
struct RpcHandlers {
    using CreateRpc = std::function<void(Service*, grpc::ServerCompletionQueue*)>;
    using ProcessIncomingRequest = std::function<void(Rpc&, const Request*)>;
    using Done = std::function<void(Rpc&, bool)>;

    /// createRpc is called when an outstanding BaseRpc starts serving an incoming RPC and we need to create the next
    /// RPC of this type to service further incoming RPCs.
    CreateRpc createRpc;

    /// processIncomingRequest is called when a new incoming request from some client has come in for this RPC.
    /// For streaming RPCs, a request from client can come in multiple times so processIncomingRequest may be called reapeatedly.
    ProcessIncomingRequest processIncomingRequest;

    // The gRPC server is done with this RPC. Any necessary clean-up must be performed when done is called.
    Done done;
};

//! Represents the RPC handlers for unary RPCs.
template <typename Service, typename Request, typename Response, template<typename, typename, typename> typename Rpc>
struct UnaryRpcHandlers : public RpcHandlers<Service, Request, Response, Rpc<Service, Request, Response>> {
    using GRPCResponder = grpc::ServerAsyncResponseWriter<Response>;
    using RequestRpc = std::function<void(Service*, grpc::ServerContext*, Request*, GRPCResponder*, grpc::CompletionQueue*, grpc::ServerCompletionQueue*, void*)>;

    // The actual queuing function on the generated service. This is called when an instance of any unary RPC is created.
    RequestRpc requestRpc;
};

//! This represents any unary (i.e. one-client-request, one-server-response model) RPC.
template <typename Service, typename Request, typename Response>
class UnaryRpc : public BaseRpc {
  public:
    using Handlers = UnaryRpcHandlers<Service, Request, Response, UnaryRpc>;

    UnaryRpc(Service* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : service_(service), queue_(queue), responder_(&context_), handlers_(handlers) {
        SILK_TRACE << "UnaryRpc::UnaryRpc START [" << this << "]";

        // Create READ/FINISH/DONE tag processors used to interact with gRPC completion queue.
        read_processor_ = [this](bool ok) { process_read(ok); };
        finish_processor_ = [this](bool ok) { process_finish(ok); };
        done_processor_ = [this](bool ok) { process_done(ok); };

        // Set up the registration to inform us when gRPC is done with this RPC.
        context_.AsyncNotifyWhenDone(&done_processor_);

        // Finally issue the async request needed by gRPC to start handling this RPC.
        SILK_DEBUG << "UnaryRpc::UnaryRpc issuing new request for service: " << service_;
        handle_started(OperationType::kRequest);
        handlers_.requestRpc(service_, &context_, &request_, &responder_, queue_, queue_, &read_processor_);
        SILK_TRACE << "UnaryRpc::UnaryRpc END new request issued [" << this << "]";
    }

    bool send_response(const Response& response) {
        handle_started(OperationType::kFinish);
        responder_.Finish(response, grpc::Status::OK, &finish_processor_);
        return true;
    }

  protected:
    /// This should be called for system level errors when no response is available.
    bool finish_with_error(const grpc::Status& error) {
        handle_started(OperationType::kFinish);
        responder_.FinishWithError(error, &finish_processor_);
        return true;
    }

  private:
    /// Tag processor for READ event in this RPC coming from gRPC framework.
    void process_read(bool ok) {
        SILK_TRACE << "UnaryRpc::process_read START [" << this << "] ok: " << ok;
        if (!ok) {
            handle_completed(OperationType::kRead);
            return;
        }

        // A request has just been activated: first create a new RPC to allow the server to handle the next request.
        handlers_.createRpc(service_, queue_);

        // The incoming request can now be handled so process it.
        if (handle_completed(OperationType::kRequest)) {
            handlers_.processIncomingRequest(*this, &request_);
        }
        SILK_TRACE << "UnaryRpc::process_read END [" << this << "]";
    }

    /// Tag processor for FINISH event in this RPC coming from gRPC framework.
    void process_finish(bool ok) {
        SILK_TRACE << "UnaryRpc::process_finish [" << this << "] ok: " << ok;
        handle_completed(OperationType::kFinish);
    }

    void cleanup() override {
        SILK_TRACE << "UnaryRpc::cleanup [" << this << "]";
        handlers_.done(*this, context_.IsCancelled());
    }

    Service* service_;
    grpc::ServerCompletionQueue* queue_;
    typename Handlers::GRPCResponder responder_;
    Handlers handlers_;
    Request request_;

    TagProcessor read_processor_;
    TagProcessor finish_processor_;
    TagProcessor done_processor_;
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_CALL_HPP_
