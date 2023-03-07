/*
   Copyright 2021 The Silkrpc Authors

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

#include "config.hpp"

#include <catch2/catch.hpp>

namespace silkrpc {

using Catch::Matchers::Message;

TEST_CASE("check configuration", "[silkrpc][config]") {
#if __has_include(<coroutine>)
    #ifdef BOOST_ASIO_HAS_CO_AWAIT
    CHECK(true);
    #else
    CHECK(false);
    #endif // BOOST_ASIO_HAS_CO_AWAIT
    #ifdef BOOST_ASIO_HAS_STD_COROUTINE
    CHECK(true);
    #else
    CHECK(false);
    #endif // BOOST_ASIO_HAS_STD_COROUTINE
#endif // __has_include(<coroutine>)
    CHECK(&typeid(std::coroutine_handle<void>) != nullptr);
    CHECK(&typeid(std::suspend_always) != nullptr);
    CHECK(&typeid(std::suspend_never) != nullptr);
}

} // namespace silkrpc

