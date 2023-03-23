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

#include "server.hpp"

namespace silkworm::execution {

using namespace std::chrono;
using namespace boost::asio;

awaitable<void> Server::start() {
    throw std::runtime_error{"Server::start not implemented"};
}

awaitable<BlockHeader> get_header(BlockNum /*block_number*/, Hash /*block_hash*/) {
    throw std::runtime_error{"Server::get_header not implemented"};
}

awaitable<BlockBody> get_body(BlockNum /*block_number*/, Hash /*block_hash*/) {
    throw std::runtime_error{"Server::get_body not implemented"};
}

awaitable<bool> is_canonical(Hash /*block_hash*/) {
    throw std::runtime_error{"Server::is_canonical not implemented"};
}

awaitable<BlockNum> get_block_num(Hash /*block_hash*/) {
    throw std::runtime_error{"Server::get_block_num not implemented"};
}

awaitable<void> Server::insert_headers(const BlockVector& /*blocks*/) {
    throw std::runtime_error{"Server::insert_headers not implemented"};
}

awaitable<void> Server::insert_bodies(const BlockVector& /*blocks*/) {
    throw std::runtime_error{"Server::insert_bodies not implemented"};
}

auto verify_chain(Hash /*head_block_hash*/) -> awaitable<stagedsync::ExecutionEngine::VerificationResult> {
    throw std::runtime_error{"Server::verify_chain not implemented"};
}

awaitable<bool> notify_fork_choice_update(Hash /*head_block_hash*/, std::optional<Hash> /*finalized_block_hash*/) {
    throw std::runtime_error{"Server::notify_fork_choice_update not implemented"};
}

}  // namespace silkworm::execution
