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

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace silkworm::execution {

using namespace std::chrono;
namespace asio = boost::asio;

Server::Server(NodeSettings& ns, db::RWAccess dba) : exec_engine_{io_context_, ns, dba} {
}

bool Server::stop() {
    io_context_.stop();
    return ActiveComponent::stop();
}

void Server::execution_loop() {
    SILK_TRACE << "execution::Server::execution_loop enter";
    exec_engine_.open();

    asio::executor_work_guard<decltype(io_context_.get_executor())> work{io_context_.get_executor()};
    io_context_.run();

    exec_engine_.close();
    SILK_TRACE << "execution::Server::execution_loop exit";
}

void Server::handle_exception(const std::exception_ptr& e) {
    // todo: dummy implementation, change it to save exception and rethrow it later
    try {
        if (e) {
            std::rethrow_exception(e);
        }
    } catch (const std::exception& ex) {
        std::cerr << "Exception in ExtendingFork::verify_chain(): " << ex.what() << "\n";
    }
}

Task<BlockNum> Server::block_progress() {
    auto lambda = [](Server* me) -> Task<BlockNum> {
        co_return me->exec_engine_.block_progress();
    };
    return asio::co_spawn(io_context_, lambda(this), asio::use_awaitable);
}

Task<BlockId> Server::last_fork_choice() {
    auto lambda = [](Server* me) -> Task<BlockId> {
        co_return me->exec_engine_.last_fork_choice();
    };
    return asio::co_spawn(io_context_, lambda(this), asio::use_awaitable);
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
Task<void> Server::insert_headers(const BlockVector& /*blocks*/) {
    throw std::runtime_error{"Server::insert_headers not implemented"};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
Task<void> Server::insert_bodies(const BlockVector& /*blocks*/) {
    throw std::runtime_error{"Server::insert_bodies not implemented"};
}

Task<void> Server::insert_blocks(const BlockVector& blocks) {
    auto lambda = [](Server* me, const BlockVector& b) -> Task<void> {
        co_return me->exec_engine_.insert_blocks(b);
    };
    return asio::co_spawn(io_context_, lambda(this, blocks), asio::use_awaitable);
}

Task<ValidationResult> Server::validate_chain(Hash head_block_hash) {
    auto lambda = [](Server* me, Hash h) -> Task<ValidationResult> {
        auto future_result = me->exec_engine_.verify_chain(h);
        auto verification = co_await future_result.get_async();

        ValidationResult validation;
        if (std::holds_alternative<stagedsync::ValidChain>(verification)) {
            auto valid_chain = std::get<stagedsync::ValidChain>(verification);
            validation = ValidChain{.current_head = valid_chain.current_head.hash};
        } else if (std::holds_alternative<stagedsync::InvalidChain>(verification)) {
            auto invalid_chain = std::get<stagedsync::InvalidChain>(verification);
            validation = InvalidChain{
                .latest_valid_head = invalid_chain.unwind_point.hash,
                .bad_block = invalid_chain.bad_block,
                .bad_headers = invalid_chain.bad_headers};
        } else if (std::holds_alternative<stagedsync::ValidationError>(verification)) {
            auto validation_error = std::get<stagedsync::ValidationError>(verification);
            validation = ValidationError{.latest_valid_head = validation_error.latest_valid_head.hash,
                                         .missing_block = {}};  // todo: provide missing_block
        } else {
            throw std::logic_error("Execution Server, unknown error");
        }
        co_return validation;
    };
    return asio::co_spawn(io_context_, lambda(this, head_block_hash), asio::use_awaitable);
}

Task<ForkChoiceApplication> Server::update_fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash) {
    auto lambda = [](Server* me, Hash h, std::optional<Hash> f) -> Task<ForkChoiceApplication> {
        bool updated = me->exec_engine_.notify_fork_choice_update(h, f);  // BLOCKING, will block the entire io_context thread

        auto last_fc = me->exec_engine_.last_fork_choice();
        ForkChoiceApplication application{
            .success = updated,
            .current_head = last_fc.hash,
            .current_height = last_fc.number};
        co_return application;
    };
    return asio::co_spawn(io_context_, lambda(this, head_block_hash, finalized_block_hash), asio::use_awaitable);
}

Task<std::optional<BlockHeader>> Server::get_header(Hash block_hash) {
    auto lambda = [](Server* me, Hash h) -> Task<std::optional<BlockHeader>> {
        co_return me->exec_engine_.get_header(h);
    };
    return asio::co_spawn(io_context_, lambda(this, block_hash), asio::use_awaitable);
}

Task<std::optional<BlockHeader>> Server::get_header(BlockNum height, Hash hash) {
    auto lambda = [](Server* me, BlockNum bn, Hash h) -> Task<std::optional<BlockHeader>> {
        co_return me->exec_engine_.get_header(bn, h);
    };
    return asio::co_spawn(io_context_, lambda(this, height, hash), asio::use_awaitable);
}

Task<std::vector<BlockHeader>> Server::get_last_headers(BlockNum limit) {
    auto lambda = [](Server* me, BlockNum l) -> Task<std::vector<BlockHeader>> {
        co_return me->exec_engine_.get_last_headers(l);
    };
    return asio::co_spawn(io_context_, lambda(this, limit), asio::use_awaitable);
}

Task<std::optional<TotalDifficulty>> Server::get_header_td(Hash hash, std::optional<BlockNum> num) {
    auto lambda = [](Server* me, Hash h, std::optional<BlockNum> bn) -> Task<std::optional<TotalDifficulty>> {
        co_return me->exec_engine_.get_header_td(h, bn);
    };
    return asio::co_spawn(io_context_, lambda(this, hash, num), asio::use_awaitable);
}

Task<std::optional<BlockBody>> Server::get_body(Hash block_hash) {
    auto lambda = [](Server* me, Hash h) -> Task<std::optional<BlockBody>> {
        co_return me->exec_engine_.get_body(h);
    };
    return asio::co_spawn(io_context_, lambda(this, block_hash), asio::use_awaitable);
}

Task<std::optional<BlockBody>> Server::get_body(BlockNum block_number) {
    auto lambda = [](Server* me, BlockNum n) -> Task<std::optional<BlockBody>> {
        co_return me->exec_engine_.get_canonical_body(n);
    };
    return asio::co_spawn(io_context_, lambda(this, block_number), asio::use_awaitable);
}

Task<bool> Server::is_canonical(Hash block_hash) {
    auto lambda = [](Server* me, Hash h) -> Task<bool> {
        co_return me->exec_engine_.is_canonical(h);
    };
    return asio::co_spawn(io_context_, lambda(this, block_hash), asio::use_awaitable);
}

Task<std::optional<BlockNum>> Server::get_block_num(Hash block_hash) {
    auto lambda = [](Server* me, Hash h) -> Task<std::optional<BlockNum>> {
        co_return me->exec_engine_.get_block_number(h);
    };
    return asio::co_spawn(io_context_, lambda(this, block_hash), asio::use_awaitable);
}

}  // namespace silkworm::execution
