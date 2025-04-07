// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#if __has_include(<coroutine>)
#include <coroutine>

#include <boost/asio/detail/config.hpp>

#elif __has_include(<experimental/coroutine>)
#include <experimental/coroutine>
namespace std {
template <typename T>
using coroutine_handle = std::experimental::coroutine_handle<T>;
using suspend_always = std::experimental::suspend_always;
using suspend_never = std::experimental::suspend_never;
}  // namespace std

#else
#error "no coroutines support"

#endif  // __has_include(<coroutine>)
