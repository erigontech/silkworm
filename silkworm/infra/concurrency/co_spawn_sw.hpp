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

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detail/type_traits.hpp>
#include <boost/asio/use_awaitable.hpp>

#define co_spawn_sw co_spawn

namespace silkworm::concurrency {

using namespace boost::asio;

template <typename Executor, typename F>
inline BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(
    boost::asio::use_awaitable,
    typename boost::asio::detail::awaitable_signature<typename boost::asio::result_of<F()>::type>::type = 0)
    co_spawn_and_await(const Executor& ex, F&& f) {
    return (co_spawn_sw)(ex, std::forward<F>(f), boost::asio::use_awaitable);
}

}  // namespace silkworm::concurrency
