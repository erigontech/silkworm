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
#include <grpcpp/impl/codegen/async_unary_call.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/completion_tag.hpp>

namespace silkworm::rpc {

//! This represents the generic gRPC call composed by a sequence of bidirectional operations.
class BaseRpc {
  public:
    static int32_t instance_count() { return instance_count_; }

    BaseRpc() {
        ++instance_count_;
        SILK_TRACE << "BaseRpc::BaseRpc [" << this << "] instances: " << instance_count_;
    }

    virtual ~BaseRpc() {
        --instance_count_;
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

        if (opType == OperationType::kRead) {
            read_in_progress_ = true;
        } else if (opType == OperationType::kWrite) {
            write_in_progress_ = true;
        }
    }

    /// Callback to handle the end of the specified async operation.
    /// \return true if the RPC processing should keep going, false otherwise
    bool handle_completed(OperationType opType) {
        --op_count_;
        SILK_TRACE << "BaseRpc::handle_completed opType: " << static_cast<int>(opType) << " op_count_: " << op_count_;

        if (opType == OperationType::kRead) {
            read_in_progress_ = false;
        } else if (opType == OperationType::kWrite) {
            write_in_progress_ = false;
        }

        if (op_count_ == 0 && done_) {
            // No async operations pending and gRPC library already notified that this RPC is done => cleanup.
            cleanup();
            return false;
        }

        return true;
    }

    /// Returns if one in-progress read operation exists or not.
    bool read_in_progress() const { return read_in_progress_; }

    /// Returns if one in-progress write operation exists or not.
    bool write_in_progress() const { return write_in_progress_; }

    //! Used to access the options and current status of the RPC.
    grpc::ServerContext context_;

    //! Keep track of the total outstanding RPC calls (intentionally signed to spot underflows).
    inline static std::atomic_int64_t instance_count_ = 0;

  private:
    //! This counts the number of pending operations in this RPC.
    /// \warning It is used to detect when the RPC is really done in some corner cases (e.g. client abruptly exits).
    uint32_t op_count_{0};

    //! Flag indicating if a read operation is in progress. At most one read at a time must be outstanding.
    bool read_in_progress_{false};

    //! Flag indicating if a write operation is in progress. At most one write at a time must be outstanding.
    bool write_in_progress_{false};

    //! Flag indicating if DONE tag processor has been called or not.
    /// \warning It is used to handle some corner cases when the completion queue dispatches tags in reverse order
    /// (e.g. client abruptly exits).
    bool done_{false};
};

//! Contains the handling functions used to customize the RPC lifecycle.
/// Any concrete RPC (unary/mono streaming/bi streaming) shall specialize RpcHandlers because each of them will use
/// a different response writer to call the gRPC library.
/// \warning Note that in gRPC async model an application must explicitly ask the gRPC server to start handling an
/// incoming RPC on a particular service: that's why createRpc exists.
template <typename AsyncService, typename Request, typename Response, template<typename, typename, typename> typename Rpc>
struct RpcHandlers {
    using CreateRpcFunc = std::function<void(AsyncService*, grpc::ServerCompletionQueue*)>;
    using ProcessRequestFunc = std::function<void(Rpc<AsyncService, Request, Response>&, const Request*)>;
    using CleanupRpcFunc = std::function<void(Rpc<AsyncService, Request, Response>&, bool)>;

    /// createRpc is called when an outstanding BaseRpc starts serving an incoming RPC and we need to create the next
    /// RPC of this type to service further incoming RPCs.
    CreateRpcFunc createRpc;

    /// processRequest is called when a new incoming request from some client has come in for this RPC.
    /// For streaming RPCs, a request from client can come in multiple times so processRequest may be called repeatedly.
    ProcessRequestFunc processRequest;

    // The gRPC server is cleanupRpc with this RPC. Any necessary clean-up must be performed when cleanupRpc is called.
    CleanupRpcFunc cleanupRpc;
};

//! Represents the RPC handlers for unary RPCs.
template <typename AsyncService, typename Request, typename Response, template<typename, typename, typename> typename Rpc>
struct UnaryRpcHandlers : public RpcHandlers<AsyncService, Request, Response, Rpc> {
    using Responder = grpc::ServerAsyncResponseWriter<Response>;
    using RequestRpcFunc = std::function<void(AsyncService*, grpc::ServerContext*, Request*, Responder*, grpc::CompletionQueue*, grpc::ServerCompletionQueue*, void*)>;

    // The request queuing function on the service. This is called when an instance of any unary RPC is created.
    RequestRpcFunc requestRpc;
};

//! This represents any unary RPC (i.e. one-client-request, one-server-response).
template <typename AsyncService, typename Request, typename Response>
class UnaryRpc : public BaseRpc {
  public:
    using Handlers = UnaryRpcHandlers<AsyncService, Request, Response, UnaryRpc>;

    UnaryRpc(AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
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

    /// Send specified message as response and finalize the unary RPC.
    bool send_response(const Response& response) {
        handle_started(OperationType::kFinish);
        responder_.Finish(response, grpc::Status::OK, &finish_processor_);
        return true;
    }

    /// Finalize the unary RPC with an application error when no response is available.
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
            handlers_.processRequest(*this, &request_);
        }
        SILK_TRACE << "UnaryRpc::process_read END [" << this << "]";
    }

    /// Tag processor for FINISH event in this RPC coming from gRPC framework.
    void process_finish(bool ok) {
        SILK_TRACE << "UnaryRpc::process_finish [" << this << "] ok: " << ok;
        handle_completed(OperationType::kFinish);
    }

    /// Free resources of this RPC because this hook is called when really done.
    void cleanup() override {
        SILK_TRACE << "UnaryRpc::cleanup [" << this << "]";
        handlers_.cleanupRpc(*this, context_.IsCancelled());
    }

    //! The gRPC generated asynchronous service.
    AsyncService* service_;

    //! The gRPC server-side completion queue used by this RPC.
    grpc::ServerCompletionQueue* queue_;

    //! The gRPC server-side API for responding back in unary calls.
    typename Handlers::Responder responder_;

    //! The lifecycle handlers for unary calls.
    Handlers handlers_;

    //! The incoming unary RPC request filled after READ tag processing.
    Request request_;

    //! The READ tag processing callback.
    TagProcessor read_processor_;

    //! The FINISH tag processing callback.
    TagProcessor finish_processor_;

    //! The DONE tag processing callback.
    TagProcessor done_processor_;
};

//! Represents the RPC handlers for server-streaming RPCs.
template <typename AsyncService, typename Request, typename Response, template<typename, typename, typename> typename Rpc>
struct ServerStreamingRpcHandlers : public RpcHandlers<AsyncService, Request, Response, Rpc> {
    using Responder = grpc::ServerAsyncWriter<Response>;
    using RequestRpcFunc = std::function<void(AsyncService*, grpc::ServerContext*, Request*, Responder*, grpc::CompletionQueue*, grpc::ServerCompletionQueue*, void*)>;

    // The request queuing function on the service. This is called when an instance of any server-streaming RPC is created.
    RequestRpcFunc requestRpc;
};

//! This represents any server-streaming RPC (i.e. one-client-request, many-server-responses).
template <typename AsyncService, typename Request, typename Response>
class ServerStreamingRpc : public BaseRpc {
  public:
    using Handlers = ServerStreamingRpcHandlers<AsyncService, Request, Response, ServerStreamingRpc>;

    ServerStreamingRpc(AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : service_(service), queue_(queue), responder_(&context_), handlers_(handlers) {
        SILK_TRACE << "ServerStreamingRpc::ServerStreamingRpc START [" << this << "]";

        // Create READ/WRITE/FINISH/DONE tag processors used to interact with gRPC completion queue.
        read_processor_ = [this](bool ok) { process_read(ok); };
        write_processor_ = [this](bool ok) { process_write(ok); };
        finish_processor_ = [this](bool ok) { process_finish(ok); };
        done_processor_ = [this](bool ok) { process_done(ok); };

        // Set up the registration to inform us when gRPC is done with this RPC.
        context_.AsyncNotifyWhenDone(&done_processor_);

        // Finally issue the async request needed by gRPC to start handling this RPC.
        SILK_DEBUG << "ServerStreamingRpc::ServerStreamingRpc issuing new request for service: " << service_;
        handle_started(OperationType::kRequest);
        handlers_.requestRpc(service_, &context_, &request_, &responder_, queue_, queue_, &read_processor_);
        SILK_TRACE << "ServerStreamingRpc::ServerStreamingRpc END new request issued [" << this << "]";
    }

    // gRPC can only do one async write at a time but that is very inconvenient from the application point of view.
    // So we buffer the response below in a queue if gRPC library is not ready for it.
    bool send_response(const Response& response) {
        response_queue_.push_back(std::move(response));

        if (!write_in_progress()) {
            write();
            return true;
        }
        return false;
    }

    /// Call this to indicate the completion of server side streaming.
    bool close() {
        streaming_done_ = true;

        if (!write_in_progress()) {
            finish();
            return true;
        }
        return false;
    }

    /// Finalize the server-streaming RPC with an application error when no response is available.
    bool finish_with_error(const grpc::Status& error) {
        handle_started(OperationType::kFinish);
        responder_.Finish(error, &finish_processor_); // FinishWithError?
        return true;
    }

  private:
    /// Tag processor for READ event in this RPC coming from gRPC framework.
    void process_read(bool ok) {
        SILK_TRACE << "ServerStreamingRpc::process_read START [" << this << "] ok: " << ok;
        if (!ok) {
            handle_completed(OperationType::kRead);
            return;
        }

        // A request has just been activated: first create a new RPC to allow the server to handle the next request.
        handlers_.createRpc(service_, queue_);

        // The incoming request can now be handled so process it.
        if (handle_completed(OperationType::kRequest)) {
            handlers_.processRequest(*this, &request_);
        }
        SILK_TRACE << "ServerStreamingRpc::process_read END [" << this << "]";
    }

    /// Tag processor for WRITE event in this RPC coming from gRPC framework.
    void process_write(bool ok) {
        SILK_TRACE << "ServerStreamingRpc::process_write START [" << this << "] ok: " << ok;
        if (handle_completed(OperationType::kWrite)) {
            // Get rid of the response that just finished.
            response_queue_.pop_front();

            if (ok) {
                if (!response_queue_.empty()) {
                    // We have more responses waiting to be sent, send first.
                    write();
                } else if (streaming_done_) {
                    // Previous write completed, no pending write and streaming finished: we're done.
                    finish();
                }
            }
        }
        SILK_TRACE << "ServerStreamingRpc::process_write END [" << this << "]";
    }

    /// Tag processor for FINISH event in this RPC coming from gRPC framework.
    void process_finish(bool ok) {
        SILK_TRACE << "ServerStreamingRpc::process_finish [" << this << "] ok: " << ok;
        handle_completed(OperationType::kFinish);
    }

    void write() {
        handle_started(OperationType::kWrite);
        responder_.Write(response_queue_.front(), &write_processor_);
    }

    void finish() {
        handle_started(OperationType::kFinish);
        responder_.Finish(grpc::Status::OK, &finish_processor_);
    }

    void cleanup() override {
        SILK_TRACE << "ServerStreamingRpc::cleanup [" << this << "]";
        handlers_.cleanupRpc(*this, context_.IsCancelled());
    }

  private:

    //! The gRPC generated asynchronous service.
    AsyncService* service_;

    //! The gRPC server-side completion queue used by this RPC.
    grpc::ServerCompletionQueue* queue_;

    //! The gRPC server-side API for responding back in server-streaming calls.
    typename Handlers::Responder responder_;

    //! The lifecycle handlers for server-streaming calls.
    Handlers handlers_;

    //! The incoming unary RPC request filled after READ tag processing.
    Request request_;

    //! The READ tag processing callback.
    TagProcessor read_processor_;

    //! The WRITE tag processing callback.
    TagProcessor write_processor_;

    //! The FINISH tag processing callback.
    TagProcessor finish_processor_;

    //! The DONE tag processing callback.
    TagProcessor done_processor_;

    //! The list of server streamed responses.
    std::list<Response> response_queue_;

    //! Flag indicating if server streaming is finished or not.
    bool streaming_done_{false};
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_CALL_HPP_
