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

    InternalMessage(ExecutionFunc);

    std::string name() const override { return "InternalMessage"; }

    void execute(db::ROAccess, HeaderChain&, BodySequence&, SentryClient&) override;

    std::future<R>& result() { return result_out_; }

    bool completed_and_read() { return !result_out_.valid(); }  // result arrived and was read

  private:
    ExecutionFunc execution_impl_;
    std::promise<R> result_in_;
    std::future<R> result_out_;
};

template <class R>
InternalMessage<R>::InternalMessage(ExecutionFunc exec)
    : execution_impl_{std::move(exec)}, result_in_{}, result_out_{result_in_.get_future()} {}

template <class R>
void InternalMessage<R>::execute(db::ROAccess, HeaderChain& hc, BodySequence& bs, SentryClient&) {
    R local_result = execution_impl_(hc, bs);

    result_in_.set_value(local_result);
}

template <>
inline void InternalMessage<void>::execute(db::ROAccess, HeaderChain& hc, BodySequence& bs, SentryClient&) {
    execution_impl_(hc, bs);

    result_in_.set_value();
}

}  // namespace silkworm
