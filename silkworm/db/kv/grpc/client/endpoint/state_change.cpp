/*
   Copyright 2024 The Silkworm Authors

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

#include "state_change.hpp"

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/infra/grpc/common/bytes.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>

namespace silkworm::db::kv::grpc::client {

namespace proto = ::remote;

proto::StateChangeRequest request_from_state_change_options(const api::StateChangeOptions& options) {
    proto::StateChangeRequest request;
    request.set_with_storage(options.with_storage);
    request.set_with_transactions(options.with_transactions);
    return request;
}

static api::Action action_from_proto(const proto::Action proto_action) {
    switch (proto_action) {
        case proto::Action::UPSERT: {
            return api::Action::kUpsert;
        }
        case proto::Action::UPSERT_CODE: {
            return api::Action::kUpsertCode;
        }
        case proto::Action::REMOVE: {
            return api::Action::kRemove;
        }
        case proto::Action::STORAGE: {
            return api::Action::kStorage;
        }
        case proto::Action::CODE: {
            return api::Action::kCode;
        }
        default: {
            SILKWORM_ASSERT(false);
            throw;
        }
    }
}

static api::StorageChangeSequence storage_changes_from_proto(const proto::AccountChange& account_change) {
    api::StorageChangeSequence storage_change_set;
    if (account_change.storage_changes_size() == 0) {
        return storage_change_set;
    }
    storage_change_set.reserve(static_cast<size_t>(account_change.storage_changes_size()));
    for (const auto& proto_storage_change : account_change.storage_changes()) {
        storage_change_set.emplace_back(api::StorageChange{
            .location = rpc::bytes32_from_h256(proto_storage_change.location()),
            .data = string_to_bytes(proto_storage_change.data()),
        });
    }
    return storage_change_set;
}

static api::AccountChangeSequence account_change_set_from_proto(const proto::StateChange& state_change) {
    api::AccountChangeSequence account_change_set;
    if (state_change.changes_size() == 0) {
        return account_change_set;
    }
    account_change_set.reserve(static_cast<size_t>(state_change.changes_size()));
    for (const auto& proto_account_change : state_change.changes()) {
        account_change_set.emplace_back(api::AccountChange{
            .address = rpc::address_from_h160(proto_account_change.address()),
            .incarnation = proto_account_change.incarnation(),
            .change_type = action_from_proto(proto_account_change.action()),
            .data = string_to_bytes(proto_account_change.data()),
            .code = string_to_bytes(proto_account_change.code()),
            .storage_changes = storage_changes_from_proto(proto_account_change),
        });
    }
    return account_change_set;
}

static api::ListOfBytes rlp_txs_from_proto(const proto::StateChange& state_change) {
    api::ListOfBytes rlp_txs;
    if (state_change.txs_size() == 0) {
        return rlp_txs;
    }
    rlp_txs.reserve(static_cast<size_t>(state_change.txs_size()));
    for (const auto& proto_txn : state_change.txs()) {
        rpc::deserialize_hex_as_bytes(proto_txn, rlp_txs);
    }
    return rlp_txs;
}

api::StateChangeSet state_change_set_from_batch(const proto::StateChangeBatch& batch) {
    api::StateChangeSet state_change_set{
        .state_version_id = batch.state_version_id(),
        .pending_block_base_fee = batch.pending_block_base_fee(),
        .block_gas_limit = batch.block_gas_limit(),
        .finalized_block = batch.finalized_block(),
        .pending_blob_fee_per_gas = batch.pending_blob_fee_per_gas(),
    };
    state_change_set.state_changes.reserve(static_cast<size_t>(batch.change_batch_size()));
    for (const auto& change : batch.change_batch()) {
        state_change_set.state_changes.emplace_back(api::StateChange{
            .direction = change.direction() == proto::Direction::FORWARD ? api::kForward : api::kUnwind,
            .block_height = change.block_height(),
            .block_hash = rpc::bytes32_from_h256(change.block_hash()),
            .account_changes = account_change_set_from_proto(change),
            .rlp_txs = rlp_txs_from_proto(change),
        });
    }
    return state_change_set;
}

}  // namespace silkworm::db::kv::grpc::client
