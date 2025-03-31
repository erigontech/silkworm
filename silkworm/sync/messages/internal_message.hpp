// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <future>
#include <utility>

#include <silkworm/sync/internals/header_chain.hpp>

#include "message.hpp"

namespace silkworm {

template <class R>
class InternalMessage : public Message {
  public:
    using ExecutionFunc = std::function<R(HeaderChain&, BodySequence&)>;

    explicit InternalMessage(ExecutionFunc);

    std::string name() const override { return "InternalMessage"; }

    void execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) override;

    std::future<R>& result() { return result_out_; }

    bool completed_and_read() { return !result_out_.valid(); }  // result arrived and was read

  private:
    ExecutionFunc execution_impl_;
    std::promise<R> result_in_{};
    std::future<R> result_out_{result_in_.get_future()};
};

template <class R>
InternalMessage<R>::InternalMessage(ExecutionFunc exec) : execution_impl_{std::move(exec)} {}

template <class R>
void InternalMessage<R>::execute(db::DataStoreRef, HeaderChain& hc, BodySequence& bs, SentryClient&) {
    R local_result = execution_impl_(hc, bs);
    result_in_.set_value(local_result);
}

template <>
inline void InternalMessage<void>::execute(db::DataStoreRef, HeaderChain& hc, BodySequence& bs, SentryClient&) {
    execution_impl_(hc, bs);
    result_in_.set_value();
}

}  // namespace silkworm
