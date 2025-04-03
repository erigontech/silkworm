// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    ExecutorDispatcher(Executor executor) : executor_{std::move(executor)} {}

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
