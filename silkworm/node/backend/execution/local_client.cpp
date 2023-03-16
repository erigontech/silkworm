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

#include "local_client.hpp"

namespace silkworm::execution {

using namespace std::chrono;
using namespace boost::asio;

LocalClient::LocalClient(Server* local_server) : local_server_(local_server) {}

awaitable<void> LocalClient::start() {
    throw std::runtime_error{"LocalClient::start not implemented"};
}

awaitable<void> LocalClient::get_header(BlockNum block_number, Hash block_hash, BlockHeader& header) {
    co_await local_server_->get_header(block_number, block_hash, header);
}

awaitable<void> LocalClient::get_body(BlockNum block_number, Hash block_hash, BlockBody& body) {
    co_await local_server_->get_body(block_number, block_hash, body);
}

awaitable<void> LocalClient::insert_headers(const BlockVector& blocks) {
    co_await local_server_->insert_headers(blocks);
}

awaitable<void> LocalClient::insert_bodies(const BlockVector& blocks) {
    co_await local_server_->insert_bodies(blocks);
}

}  // namespace silkworm::execution
