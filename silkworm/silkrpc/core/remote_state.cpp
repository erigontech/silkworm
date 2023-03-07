/*
    Copyright 2020 The Silkrpc Authors

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

#include "remote_state.hpp"

#include <future>
#include <unordered_map>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <silkworm/core/common/util.hpp>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>

namespace silkrpc::state {

static std::unordered_map<evmc::bytes32, silkworm::Bytes> code;

boost::asio::awaitable<std::optional<silkworm::Account>> AsyncRemoteState::read_account(const evmc::address& address) const noexcept {
    co_return co_await state_reader_.read_account(address, block_number_ + 1);
}

boost::asio::awaitable<silkworm::ByteView> AsyncRemoteState::read_code(const evmc::bytes32& code_hash) const noexcept {
    const auto optional_code{co_await state_reader_.read_code(code_hash)};
    if (optional_code) {
        code[code_hash] = std::move(*optional_code);
        co_return code[code_hash]; // NOLINT(runtime/arrays)
    }
    co_return silkworm::ByteView{};
}

boost::asio::awaitable<evmc::bytes32> AsyncRemoteState::read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept {
    co_return co_await state_reader_.read_storage(address, incarnation, location, block_number_ + 1);
}

boost::asio::awaitable<uint64_t> AsyncRemoteState::previous_incarnation(const evmc::address& address) const noexcept {
    co_return 0;
}

boost::asio::awaitable<std::optional<silkworm::BlockHeader>> AsyncRemoteState::read_header(uint64_t block_number, const evmc::bytes32& block_hash) const noexcept {
    co_return co_await core::rawdb::read_header(db_reader_, block_hash, block_number);
}

boost::asio::awaitable<bool> AsyncRemoteState::read_body(uint64_t block_number, const evmc::bytes32& block_hash, silkworm::BlockBody& filled_body) const noexcept {
    filled_body = co_await core::rawdb::read_body(db_reader_, block_hash, block_number);
    co_return true;
}

boost::asio::awaitable<std::optional<intx::uint256>> AsyncRemoteState::total_difficulty(uint64_t block_number, const evmc::bytes32& block_hash) const noexcept {
    co_return co_await core::rawdb::read_total_difficulty(db_reader_, block_hash, block_number);
}

boost::asio::awaitable<evmc::bytes32> AsyncRemoteState::state_root_hash() const {
    co_return evmc::bytes32{};
}

boost::asio::awaitable<uint64_t> AsyncRemoteState::current_canonical_block() const {
    // This method should not be called by EVM::execute
    co_return 0;
}

boost::asio::awaitable<std::optional<evmc::bytes32>> AsyncRemoteState::canonical_hash(uint64_t block_number) const {
    // This method should not be called by EVM::execute
    co_return co_await core::rawdb::read_canonical_block_hash(db_reader_, block_number);
}

std::optional<silkworm::Account> RemoteState::read_account(const evmc::address& address) const noexcept {
    SILKRPC_DEBUG << "RemoteState::read_account address=" << address << " start\n";
    try {
        std::future<std::optional<silkworm::Account>> result{boost::asio::co_spawn(io_context_, async_state_.read_account(address), boost::asio::use_future)};
        const auto optional_account{result.get()};
        SILKRPC_DEBUG << "RemoteState::read_account account.nonce=" << (optional_account ? optional_account->nonce : 0) << " end\n";
        return optional_account;
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "RemoteState::read_account exception: " << e.what() << "\n";
        return std::nullopt;
    }
}

silkworm::ByteView RemoteState::read_code(const evmc::bytes32& code_hash) const noexcept {
    SILKRPC_DEBUG << "RemoteState::read_code code_hash=" << code_hash << " start\n";
    try {
        std::future<silkworm::ByteView> result{boost::asio::co_spawn(io_context_, async_state_.read_code(code_hash), boost::asio::use_future)};
        const auto code{result.get()};
        return code;
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "RemoteState::read_code exception: " << e.what() << "\n";
        return silkworm::ByteView{};
    }
}

evmc::bytes32 RemoteState::read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept {
    SILKRPC_DEBUG << "RemoteState::read_storage address=" << address << " incarnation=" << incarnation << " location=" << location << " start\n";
    try {
        std::future<evmc::bytes32> result{boost::asio::co_spawn(io_context_, async_state_.read_storage(address, incarnation, location), boost::asio::use_future)};
        const auto storage_value{result.get()};
        SILKRPC_DEBUG << "RemoteState::read_storage storage_value=" << storage_value << " end\n";
        return storage_value;
    } catch (const std::exception& e) {
       SILKRPC_ERROR << "RemoteState::read_storage exception: " << e.what() << "\n";
       return evmc::bytes32{};
    }
}

uint64_t RemoteState::previous_incarnation(const evmc::address& address) const noexcept {
    SILKRPC_DEBUG << "RemoteState::previous_incarnation address=" << address << "\n";
    return 0;
}

std::optional<silkworm::BlockHeader> RemoteState::read_header(uint64_t block_number, const evmc::bytes32& block_hash) const noexcept {
    SILKRPC_DEBUG << "RemoteState::read_header block_number=" << block_number << " block_hash=" << block_hash << "\n";
    try {
        std::future<std::optional<silkworm::BlockHeader>> result{boost::asio::co_spawn(io_context_, async_state_.read_header(block_number, block_hash), boost::asio::use_future)};
        const auto optional_header{result.get()};
        SILKRPC_DEBUG << "RemoteState::read_header block_number=" << block_number << " block_hash=" << block_hash << "\n";
        return optional_header;
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "RemoteState::read_header exception: " << e.what() << "\n";
        return std::nullopt;
    }
}

bool RemoteState::read_body(uint64_t block_number, const evmc::bytes32& block_hash, silkworm::BlockBody& filled_body) const noexcept {
    SILKRPC_DEBUG << "RemoteState::read_body block_number=" << block_number << " block_hash=" << block_hash << "\n";
    try {
        auto result{boost::asio::co_spawn(io_context_, async_state_.read_body(block_number, block_hash, filled_body), boost::asio::use_future)};
        SILKRPC_DEBUG << "RemoteState::read_body block_number=" << block_number << " block_hash=" << block_hash << "\n";
        return result.get();
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "RemoteState::read_body exception: " << e.what() << "\n";
        return false;
    }
}

std::optional<intx::uint256> RemoteState::total_difficulty(uint64_t block_number, const evmc::bytes32& block_hash) const noexcept {
    SILKRPC_DEBUG << "RemoteState::total_difficulty block_number=" << block_number << " block_hash=" << block_hash << "\n";
    try {
        std::future<std::optional<intx::uint256>> result{boost::asio::co_spawn(io_context_, async_state_.total_difficulty(block_number, block_hash), boost::asio::use_future)};
        const auto optional_total_difficulty{result.get()};
        SILKRPC_DEBUG << "RemoteState::total_difficulty block_number=" << block_number << " block_hash=" << block_hash << "\n";
        return optional_total_difficulty;
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "RemoteState::total_difficulty exception: " << e.what() << "\n";
        return std::nullopt;
    }
}

evmc::bytes32 RemoteState::state_root_hash() const {
    SILKRPC_DEBUG << "RemoteState::state_root_hash\n";
    return evmc::bytes32{};
}

uint64_t RemoteState::current_canonical_block() const {
    SILKRPC_DEBUG << "RemoteState::current_canonical_block\n";
    return 0;
}

std::optional<evmc::bytes32> RemoteState::canonical_hash(uint64_t block_number) const {
    SILKRPC_DEBUG << "RemoteState::canonical_hash block_number=" << block_number << "\n";
    return std::nullopt;
}

} // namespace silkrpc::state
