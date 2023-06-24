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

#include <silkworm/node/stagedsync/server.hpp>

namespace silkworm::execution {

using namespace std::chrono;
using namespace boost::asio;

LocalClient::LocalClient(Server& local_server) : local_server_(local_server) {}

asio::io_context& LocalClient::get_executor() {
    return local_server_.get_executor();
}

awaitable<BlockNum> LocalClient::block_progress() {
    co_return co_await local_server_.block_progress();
}

awaitable<BlockId> LocalClient::last_fork_choice() {
    co_return co_await local_server_.last_fork_choice();
}

awaitable<void> LocalClient::insert_headers(const BlockVector& blocks) {
    co_await local_server_.insert_headers(blocks);
}

awaitable<void> LocalClient::insert_bodies(const BlockVector& blocks) {
    co_await local_server_.insert_bodies(blocks);
}

awaitable<void> LocalClient::insert_blocks(const BlockVector& blocks) {
    co_await local_server_.insert_blocks(blocks);
}

awaitable<ValidationResult> LocalClient::validate_chain(Hash head_block_hash) {
    co_return co_await local_server_.validate_chain(head_block_hash);
}

awaitable<ForkChoiceApplication> LocalClient::update_fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash) {
    co_return co_await local_server_.update_fork_choice(head_block_hash, finalized_block_hash);
}

awaitable<std::optional<BlockHeader>> LocalClient::get_header(Hash block_hash) {
    co_return co_await local_server_.get_header(block_hash);
}

awaitable<std::optional<BlockHeader>> LocalClient::get_header(BlockNum height, Hash hash) {
    co_return co_await local_server_.get_header(height, hash);
}

awaitable<std::optional<BlockBody>> LocalClient::get_body(Hash block_hash) {
    co_return co_await local_server_.get_body(block_hash);
}

asio::awaitable<std::optional<BlockBody>> LocalClient::get_body(BlockNum block_number) {
    co_return co_await local_server_.get_body(block_number);
}

awaitable<bool> LocalClient::is_canonical(Hash block_hash) {
    co_return co_await local_server_.is_canonical(block_hash);
}

awaitable<std::optional<BlockNum>> LocalClient::get_block_num(Hash block_hash) {
    co_return co_await local_server_.get_block_num(block_hash);
}

awaitable<std::vector<BlockHeader>> LocalClient::get_last_headers(BlockNum limit) {
    co_return co_await local_server_.get_last_headers(limit);
}

awaitable<std::optional<TotalDifficulty>> LocalClient::get_header_td(Hash h, std::optional<BlockNum> bn) {
    co_return co_await local_server_.get_header_td(h, bn);
}

}  // namespace silkworm::execution
