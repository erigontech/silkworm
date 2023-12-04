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

#include "remote_state.hpp"

#include <future>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_future.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/rawdb/chain.hpp>

namespace silkworm::rpc::state {

std::unordered_map<evmc::bytes32, silkworm::Bytes> AsyncRemoteState::code_;

Task<std::optional<silkworm::Account>> AsyncRemoteState::read_account(const evmc::address& address) const noexcept {
    co_return co_await state_reader_.read_account(address, block_number_ + 1);
}

Task<silkworm::ByteView> AsyncRemoteState::read_code(const evmc::bytes32& code_hash) const noexcept {
    const auto optional_code{co_await state_reader_.read_code(code_hash)};
    if (optional_code) {
        code_[code_hash] = std::move(*optional_code);
        co_return code_[code_hash];  // NOLINT(runtime/arrays)
    }
    co_return silkworm::ByteView{};
}

Task<evmc::bytes32> AsyncRemoteState::read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept {
    co_return co_await state_reader_.read_storage(address, incarnation, location, block_number_ + 1);
}

Task<uint64_t> AsyncRemoteState::previous_incarnation(const evmc::address& /*address*/) const noexcept {
    co_return 0;
}

Task<std::optional<silkworm::BlockHeader>> AsyncRemoteState::read_header(BlockNum block_number, const evmc::bytes32& block_hash) const noexcept {
    co_return co_await storage_.read_header(block_number, block_hash);
}

Task<bool> AsyncRemoteState::read_body(BlockNum block_number, const evmc::bytes32& block_hash, silkworm::BlockBody& filled_body) const noexcept {
    co_return co_await storage_.read_body(block_hash, block_number, filled_body);
}

Task<std::optional<intx::uint256>> AsyncRemoteState::total_difficulty(BlockNum block_number, const evmc::bytes32& block_hash) const noexcept {
    co_return co_await storage_.read_total_difficulty(block_hash, block_number);
}

Task<evmc::bytes32> AsyncRemoteState::state_root_hash() const {
    co_return evmc::bytes32{};
}

Task<BlockNum> AsyncRemoteState::current_canonical_block() const {
    // This method should not be called by EVM::execute
    co_return 0;
}

Task<std::optional<evmc::bytes32>> AsyncRemoteState::canonical_hash(BlockNum block_number) const {
    // This method should not be called by EVM::execute
    co_return co_await storage_.read_canonical_hash(block_number);
}

std::optional<silkworm::Account> RemoteState::read_account(const evmc::address& address) const noexcept {
    SILK_DEBUG << "RemoteState::read_account address=" << address << " start";
    try {
        std::future<std::optional<silkworm::Account>> result{boost::asio::co_spawn(executor_, async_state_.read_account(address), boost::asio::use_future)};
        const auto optional_account{result.get()};
        SILK_DEBUG << "RemoteState::read_account account.nonce=" << (optional_account ? optional_account->nonce : 0) << " end";
        return optional_account;
    } catch (const std::exception& e) {
        SILK_ERROR << "RemoteState::read_account exception: " << e.what();
        return std::nullopt;
    }
}

silkworm::ByteView RemoteState::read_code(const evmc::bytes32& code_hash) const noexcept {
    SILK_DEBUG << "RemoteState::read_code code_hash=" << to_hex(code_hash) << " start";
    try {
        std::future<silkworm::ByteView> result{boost::asio::co_spawn(executor_, async_state_.read_code(code_hash), boost::asio::use_future)};
        const auto code{result.get()};
        return code;
    } catch (const std::exception& e) {
        SILK_ERROR << "RemoteState::read_code exception: " << e.what();
        return silkworm::ByteView{};
    }
}

evmc::bytes32 RemoteState::read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept {
    SILK_DEBUG << "RemoteState::read_storage address=" << address << " incarnation=" << incarnation << " location=" << to_hex(location) << " start";
    try {
        std::future<evmc::bytes32> result{boost::asio::co_spawn(executor_, async_state_.read_storage(address, incarnation, location), boost::asio::use_future)};
        const auto storage_value{result.get()};
        SILK_DEBUG << "RemoteState::read_storage storage_value=" << to_hex(storage_value) << " end\n";
        return storage_value;
    } catch (const std::exception& e) {
        SILK_ERROR << "RemoteState::read_storage exception: " << e.what();
        return evmc::bytes32{};
    }
}

uint64_t RemoteState::previous_incarnation(const evmc::address& address) const noexcept {
    SILK_DEBUG << "RemoteState::previous_incarnation address=" << address;
    return 0;
}

std::optional<silkworm::BlockHeader> RemoteState::read_header(BlockNum block_number, const evmc::bytes32& block_hash) const noexcept {
    SILK_DEBUG << "RemoteState::read_header block_number=" << block_number << " block_hash=" << to_hex(block_hash);
    try {
        std::future<std::optional<silkworm::BlockHeader>> result{boost::asio::co_spawn(executor_, async_state_.read_header(block_number, block_hash), boost::asio::use_future)};
        auto optional_header{result.get()};
        SILK_DEBUG << "RemoteState::read_header block_number=" << block_number << " block_hash=" << to_hex(block_hash);
        return optional_header;
    } catch (const std::exception& e) {
        SILK_ERROR << "RemoteState::read_header exception: " << e.what();
        return std::nullopt;
    }
}

bool RemoteState::read_body(BlockNum block_number, const evmc::bytes32& block_hash, silkworm::BlockBody& filled_body) const noexcept {
    SILK_DEBUG << "RemoteState::read_body block_number=" << block_number << " block_hash=" << to_hex(block_hash);
    try {
        auto result{boost::asio::co_spawn(executor_, async_state_.read_body(block_number, block_hash, filled_body), boost::asio::use_future)};
        SILK_DEBUG << "RemoteState::read_body block_number=" << block_number << " block_hash=" << to_hex(block_hash);
        return result.get();
    } catch (const std::exception& e) {
        SILK_ERROR << "RemoteState::read_body exception: " << e.what();
        return false;
    }
}

std::optional<intx::uint256> RemoteState::total_difficulty(BlockNum block_number, const evmc::bytes32& block_hash) const noexcept {
    SILK_DEBUG << "RemoteState::total_difficulty block_number=" << block_number << " block_hash=" << to_hex(block_hash);
    try {
        std::future<std::optional<intx::uint256>> result{boost::asio::co_spawn(executor_, async_state_.total_difficulty(block_number, block_hash), boost::asio::use_future)};
        const auto optional_total_difficulty{result.get()};
        SILK_DEBUG << "RemoteState::total_difficulty block_number=" << block_number << " block_hash=" << to_hex(block_hash);
        return optional_total_difficulty;
    } catch (const std::exception& e) {
        SILK_ERROR << "RemoteState::total_difficulty exception: " << e.what();
        return std::nullopt;
    }
}

evmc::bytes32 RemoteState::state_root_hash() const {
    throw std::logic_error{"RemoteState::state_root_hash not yet implemented"};
}

BlockNum RemoteState::current_canonical_block() const {
    throw std::logic_error{"RemoteState::current_canonical_block not yet implemented"};
}

std::optional<evmc::bytes32> RemoteState::canonical_hash(BlockNum /*block_number*/) const {
    throw std::logic_error{"RemoteState::canonical_hash not yet implemented"};
}

}  // namespace silkworm::rpc::state
