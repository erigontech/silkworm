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

#include "local_ip_resolver.hpp"

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/this_coro.hpp>

namespace silkworm::sentry::nat {

using namespace boost::asio;
using namespace boost::asio::ip;

Task<address> local_ip_resolver() {
    auto executor = co_await this_coro::executor;
    udp::socket socket(executor);
    socket.connect(udp::endpoint{make_address("1.1.1.1"), 53});
    co_return socket.local_endpoint().address();
}

}  // namespace silkworm::sentry::nat
