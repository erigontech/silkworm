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

#include "remote_chain_storage.hpp"

#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>

namespace silkworm::rpc {

// TODO(canepat) reading from db remotely for recent blocks is still missing

RemoteChainStorage::RemoteChainStorage(const DatabaseReader& reader, ethbackend::BackEnd* backend)
    : reader_{reader}, backend_{backend} {}

Task<std::optional<silkworm::ChainConfig>> RemoteChainStorage::read_chain_config() const {
    const auto rpc_chain_config{co_await core::rawdb::read_chain_config(reader_)};
    co_return silkworm::ChainConfig::from_json(rpc_chain_config.config);
}

Task<std::optional<ChainId>> RemoteChainStorage::read_chain_id() const {
    co_return co_await core::rawdb::read_chain_id(reader_);
}

Task<BlockNum> RemoteChainStorage::highest_block_number() const {
    throw std::logic_error{"RemoteChainStorage::highest_block_number not implemented"};
}

Task<std::optional<BlockNum>> RemoteChainStorage::read_block_number(const Hash& hash) const {
    silkworm::Block block;
    const bool success = co_await backend_->get_block({.hash = hash.bytes}, /*.read_senders=*/false, block);
    std::optional<BlockNum> number;
    if (success) {
        number = block.header.number;
    }
    co_return number;
}

Task<bool> RemoteChainStorage::read_block(HashAsSpan hash, BlockNum number, bool read_senders, silkworm::Block& block) const {
    co_return co_await backend_->get_block({number, hash}, read_senders, block);
}

Task<bool> RemoteChainStorage::read_block(const Hash& hash, BlockNum number, silkworm::Block& block) const {
    co_return co_await backend_->get_block({number, hash.bytes}, /*.read_senders=*/false, block);
}

Task<bool> RemoteChainStorage::read_block(const Hash& hash, silkworm::Block& block) const {
    co_return co_await backend_->get_block({.hash = hash.bytes}, /*.read_senders=*/false, block);
}

Task<std::optional<BlockHeader>> RemoteChainStorage::read_header(BlockNum number, HashAsArray hash) const {
    silkworm::Block block;
    const bool success = co_await backend_->get_block({number, hash}, /*.read_senders=*/false, block);
    std::optional<BlockHeader> header;
    if (success) {
        header = std::move(block.header);
    }
    co_return header;
}

Task<std::optional<BlockHeader>> RemoteChainStorage::read_header(BlockNum number, const Hash& hash) const {
    co_return co_await read_header(number, hash.bytes);
}

Task<std::optional<BlockHeader>> RemoteChainStorage::read_header(const Hash& hash) const {
    silkworm::Block block;
    const bool success = co_await backend_->get_block({.hash = hash.bytes}, /*.read_senders=*/false, block);
    std::optional<BlockHeader> header;
    if (success) {
        header = std::move(block.header);
    }
    co_return header;
}

Task<std::vector<BlockHeader>> RemoteChainStorage::read_sibling_headers(BlockNum /*number*/) const {
    throw std::logic_error{"RemoteChainStorage::read_sibling_headers not implemented"};
}

Task<bool> RemoteChainStorage::read_body(BlockNum number, HashAsArray hash, bool read_senders, BlockBody& body) const {
    silkworm::Block block;
    const bool success = co_await backend_->get_block({number, hash}, read_senders, block);
    if (!success) {
        co_return false;
    }
    body.transactions = std::move(block.transactions);
    body.ommers = std::move(block.ommers);
    body.withdrawals = std::move(block.withdrawals);
    co_return true;
}

Task<bool> RemoteChainStorage::read_body(const Hash& hash, BlockNum number, BlockBody& body) const {
    co_return co_await read_body(number, hash.bytes, /*.read_senders=*/false, body);
}

Task<bool> RemoteChainStorage::read_body(const Hash& hash, BlockBody& body) const {
    silkworm::Block block;
    const bool success = co_await backend_->get_block({.hash = hash.bytes}, /*.read_senders=*/false, block);
    if (!success) {
        co_return false;
    }
    body.transactions = std::move(block.transactions);
    body.ommers = std::move(block.ommers);
    body.withdrawals = std::move(block.withdrawals);
    co_return true;
}

Task<std::optional<Hash>> RemoteChainStorage::read_canonical_hash(BlockNum number) const {
    silkworm::Block block;
    const bool success = co_await backend_->get_block({.number = number}, /*.read_senders=*/false, block);
    std::optional<Hash> hash;
    if (success) {
        hash = block.header.hash();
    }
    co_return hash;
}

Task<std::optional<BlockHeader>> RemoteChainStorage::read_canonical_header(BlockNum number) const {
    silkworm::Block block;
    const bool success = co_await backend_->get_block({.number = number}, /*.read_senders=*/false, block);
    std::optional<BlockHeader> header;
    if (success) {
        header = std::move(block.header);
    }
    co_return header;
}

Task<bool> RemoteChainStorage::read_canonical_body(BlockNum number, BlockBody& body) const {
    silkworm::Block block;
    const bool success = co_await backend_->get_block({.number = number}, /*.read_senders=*/false, block);
    if (!success) {
        co_return false;
    }
    body.transactions = std::move(block.transactions);
    body.ommers = std::move(block.ommers);
    body.withdrawals = std::move(block.withdrawals);
    co_return true;
}

Task<bool> RemoteChainStorage::read_canonical_block(BlockNum number, silkworm::Block& block) const {
    const bool success = co_await backend_->get_block({.number = number}, /*.read_senders=*/false, block);
    if (!success) {
        co_return false;
    }
    co_return true;
}

Task<bool> RemoteChainStorage::has_body(BlockNum number, HashAsArray hash) const {
    BlockBody body;
    co_return co_await read_body(number, hash, /*.read_senders=*/false, body);
}

Task<bool> RemoteChainStorage::has_body(BlockNum number, const Hash& hash) const {
    BlockBody body;
    co_return co_await read_body(hash, number, body);
}

Task<bool> RemoteChainStorage::read_rlp_transactions(BlockNum number, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const {
    silkworm::Block block;
    const bool success = co_await backend_->get_block({number, hash.bytes}, /*.read_senders=*/false, block);
    if (!success) {
        co_return false;
    }
    rlp_txs.reserve(block.transactions.size());
    for (const auto& transaction : block.transactions) {
        rlp::encode(rlp_txs.emplace_back(), transaction);
    }
    co_return true;
}

Task<intx::uint256> RemoteChainStorage::read_total_difficulty(const Hash& /*block_hash*/, BlockNum /*block_number*/) const {
    throw std::logic_error{"RemoteChainStorage::read_total_difficulty"};
}

}  // namespace silkworm::rpc
