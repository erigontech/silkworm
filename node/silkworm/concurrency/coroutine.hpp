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

// The utility header is required to resolve an issue with boost asio:
// https://github.com/boostorg/asio/commit/71964b22c7fade69cc4caa1c869a868e3a32cc97
// It could be removed after upgrading to Boost 1.79.
#include <utility>

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
