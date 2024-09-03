/*
   Copyright 2023 The Silkworm Authors

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

#include <utility>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/compose.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/append.hpp>

namespace silkworm::detail {

template <typename Executor>
class ExecutorDispatcher {
  public:
    template <typename CompletionToken, typename... Args>
    void dispatch(CompletionToken&& token, Args&&... args) {
        boost::asio::dispatch(
            boost::asio::bind_executor(executor_,
                                       boost::asio::append(std::forward<CompletionToken>(token),
                                                           std::forward<Args>(args)...)));
    }

  private:
    Executor executor_;
};

struct InlineDispatcher {
    template <typename CompletionToken, typename... Args>
    void dispatch(CompletionToken&& token, Args&&... args) {
        std::forward<CompletionToken>(token)(std::forward<Args>(args)...);
    }
};

}  // namespace silkworm::detail
