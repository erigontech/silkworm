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

#ifndef SILKWORM_INTERNALMESSAGE_HPP
#define SILKWORM_INTERNALMESSAGE_HPP

#include <future>

#include <silkworm/downloader/internals/persisted_chain.hpp>
#include <silkworm/downloader/internals/working_chain.hpp>

#include "Message.hpp"

namespace silkworm {

template <class R>
class InternalMessage : public Message {
  public:
    using ExecutionFunc = std::function<R(WorkingChain&)>;

    InternalMessage(WorkingChain&, ExecutionFunc);

    std::string name() const override { return "InternalMessage"; }

    void execute() override;

    std::future<R> result() { return result_.get_future(); }

  private:
    WorkingChain& working_chain_;
    ExecutionFunc execution_impl_;

    std::promise<R> result_;
};

template <class R>
InternalMessage<R>::InternalMessage(WorkingChain& wc, ExecutionFunc exec) : working_chain_(wc), execution_impl_(exec) {}

template <class R>
void InternalMessage<R>::execute() {
    R local_result = execution_impl_(working_chain_);

    result_.set_value(local_result);
}

template <>
inline void InternalMessage<void>::execute() {
    execution_impl_(working_chain_);

    result_.set_value();
}

}  // namespace silkworm
#endif  // SILKWORM_INTERNALMESSAGE_HPP
