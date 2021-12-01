/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_GRPC_SYNC_CLIENT_HPP
#define SILKWORM_GRPC_SYNC_CLIENT_HPP

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "types.hpp"

namespace silkworm::rpc {

template <class STUB>
class Client;

// CallException
// ---------------------------------------------------------------------------------------------------------- A generic
// RPC exception
class CallException : public std::runtime_error {
  public:
    explicit CallException(std::string cause) : std::runtime_error(cause) {}
};

// Call ----------------------------------------------------------------------------------------------------------
// A generic RPC call
// Note: using an object to represent a sync call give us more flexibility (e.g. an RPC can be canceled) and simplifies
// the code with long-lived RPCs (streaming calls).
template <class STUB>
class Call {
  public:
    using call_t = Call<STUB>;
    using callback_t = std::function<void(Call&)>;

    // See concrete implementation for a public constructor
    // Use AsyncClient to send this call to a remote server

    // Virtual destructor allows correct child destruction
    virtual ~Call() = default;

    // Set a callback that will be called on reply arrival from the server
    void on_receive_reply(callback_t f) { callback_ = f; }

    void try_cancel() { context_.TryCancel(); }

    // True if terminated (some async call have one round trip others many)
    virtual bool terminated() { return terminated_; };

    // Status of the RPC upon completion
    grpc::Status status() {
        if (!terminated_) throw std::logic_error("Call status not ready");
        return status_;
    }

    // name of this call
    std::string name() { return name_; }

  protected:
    friend class Client<STUB>;  // only to give access to execute()

    // Execute the remote proc call sending request to the server
    virtual void execute(typename STUB::Stub* stub) = 0;

    // Will be called on response arrival from the server
    virtual void reply_received() {
        if (call_t::callback_) call_t::callback_(*this);  // use status & reply
    }

    // See concrete implementations for a public constructor
    explicit Call(std::string name) : name_(std::move(name)) {}

    // Name, used for logging purposes
    std::string name_;

    // Call-context, it could be used to convey extra information to the server and/or tweak certain RPC behaviors
    grpc::ClientContext context_;

    // Status of the RPC upon completion
    grpc::Status status_;

    // Callback that will be called on completion (i.e. response arrival)
    callback_t callback_;

    // True if terminated (some async call have one round trip others many)
    bool terminated_ = false;
};

// Client ----------------------------------------------------------------------------------------------------
// A generic RPC client to execute remotely a call
template <class STUB>
class Client {
  public:
    using stub_t = STUB;
    using call_t = Call<STUB>;

    // build a client upon a channel
    explicit Client(std::shared_ptr<grpc::Channel> channel) : channel_(channel), stub_(stub_t::NewStub(channel)) {}

    // execute remotely a procedure
    void exec_remotely(call_t& call) {
        call.execute(stub_.get());  // provide the stub to the call, it is the call that know what procedure to execute
    }

  protected:
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<typename STUB::Stub> stub_;  // the stub class generated from grpc proto
};

// UnaryCall ----------------------------------------------------------------------------------------------------------
// A RPC call with only one result
template <class STUB, class REQUEST, class REPLY>
class UnaryCall : public Call<STUB> {
  public:
    using base_t = Call<STUB>;
    using request_t = REQUEST;
    using reply_t = REPLY;
    using procedure_t = grpc::Status (STUB::Stub::*)(grpc::ClientContext* context, const request_t& request,
                                                     reply_t* reply);
    using base_t::status_, base_t::context_, base_t::terminated_;

    UnaryCall(std::string name, procedure_t proc, request_t request)
        : base_t{std::move(name)}, procedure_{proc}, request_{std::move(request)} {
        context_.set_wait_for_ready(true); // not fail if the channel is in TRANSIENT_FAILURE, instead queue the RPCs
                                           // until the channel is READY.
    }                                      // When channel is in CONNECTING, READY, or IDLE it doesn't fail anyway

    void deadline(time_point_t tp) { context_.set_deadline(tp); }
    void do_not_throw_on_failure() { not_throw_on_failure_ = true; }

    void timeout(seconds_t delta) {
        time_point_t deadline = std::chrono::system_clock::now() + delta;
        context_.set_deadline(deadline);
    }

    virtual ~UnaryCall() = default;

    // Direct access to the reply
    reply_t& reply() { return reply_; }  // use on_receive_reply(callback_t f) for a callback style access

  protected:
    void execute(typename STUB::Stub* stub) override {
        status_ = (stub->*procedure_)(&context_, request_, &reply_);  // invoke remotely

        terminated_ = true;

        if (!not_throw_on_failure_ && !status_.ok()) {
            throw CallException("UnaryCall exception, cause: " + status_.error_message());
        }

        base_t::reply_received();
    }

    procedure_t procedure_;  // The remote procedure to call

    request_t request_;  // Container for the request we send to the server

    reply_t reply_;  // Container for the data we expect from the server.

    bool not_throw_on_failure_{false};
};

// OutStreamingCall ----------------------------------------------------------------------------------------------
// A generic RPC call with a stream of replies
template <class STUB, class REQUEST, class REPLY>
class OutStreamingCall : public Call<STUB> {
  public:
    using base_t = Call<STUB>;
    using request_t = REQUEST;
    using reply_t = REPLY;
    using reply_reader_t = std::unique_ptr<::grpc::ClientReader<reply_t>>;
    using procedure_t = reply_reader_t (STUB::Stub::*)(grpc::ClientContext* context, const request_t& request);
    using base_t::status_, base_t::context_, base_t::terminated_;

    OutStreamingCall(std::string name, procedure_t proc, const request_t& request)
        : base_t{std::move(name)}, procedure_{proc}, request_{std::move(request)} {}

    ~OutStreamingCall() {
        if (!base_t::terminated_) {
            status_ = reply_reader_->Finish();
        }
    }

    bool receive_one_reply() {
        if (!started_) throw std::logic_error("OutStreamingCall exception, cause: read on not started call");

        if (terminated_) throw std::logic_error("OutStreamingCall exception, cause: read on terminated call");

        reply_ = {};
        bool has_reply = reply_reader_->Read(&reply_);

        if (has_reply) {
            base_t::reply_received();
        } else {
            status_ = reply_reader_->Finish();
            terminated_ = true;
        }

        if (!status_.ok()) throw CallException("OutStreamingCall exception, cause: " + status_.error_message());

        return has_reply;
    }

    // Direct access to the reply
    reply_t& reply() { return reply_; }  // use on_receive_reply(callback_t f) for a callback style access

  protected:
    void execute(typename STUB::Stub* stub) override {
        reply_reader_ = (stub->*procedure_)(&context_, request_);  // invoke remotely

        if (reply_reader_ == nullptr) throw CallException("OutStreamingCall exception, null response reader");

        started_ = true;
    }

    procedure_t procedure_;  // pointer to the method of the Stub (remote procedure)

    reply_reader_t reply_reader_;  // reply stream reader

    request_t request_;  // Container for the request we send to the server

    reply_t reply_;  // Container for the data we expect from the server.

    bool started_ = false;  // if started we can call read_one_reply()
};

}  // namespace silkworm::rpc

#endif  // SILKWORM_GRPC_SYNC_CLIENT_HPP
