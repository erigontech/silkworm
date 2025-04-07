// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/test_util/sample_blocks.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>
#include <silkworm/interfaces/types/types.pb.h>

namespace silkworm::execution::test_util {

using namespace silkworm::test_util;
namespace proto = ::execution;

inline void sample_proto_header(proto::Header* header) {
    header->set_allocated_parent_hash(rpc::h256_from_bytes32(kSampleParentHash).release());
    header->set_allocated_ommer_hash(rpc::h256_from_bytes32(kSampleOmmersHash).release());
    header->set_allocated_coinbase(rpc::h160_from_address(kSampleBeneficiary).release());
    header->set_allocated_state_root(rpc::h256_from_bytes32(kSampleStateRoot).release());
    header->set_allocated_transaction_hash(rpc::h256_from_bytes32(kSampleTransactionsRoot).release());
    header->set_allocated_receipt_root(rpc::h256_from_bytes32(kSampleReceiptsRoot).release());
    header->set_allocated_difficulty(rpc::h256_from_uint256(kSampleDifficulty).release());
    header->set_block_number(kSampleBlockNum);
    header->set_gas_limit(kSampleGasLimit);
    header->set_gas_used(kSampleGasUsed);
    header->set_timestamp(kSampleTimestamp);
    header->set_extra_data(byte_ptr_cast(kSampleExtraData.data()), kSampleExtraData.size());
    header->set_allocated_prev_randao(rpc::h256_from_bytes32(kSamplePrevRandao).release());
    header->set_nonce(endian::load_big_u64(kSampleNonce.data()));
    header->set_allocated_base_fee_per_gas(rpc::h256_from_uint256(kSampleBaseFeePerGas).release());
}

inline proto::Header sample_proto_header() {
    proto::Header header;
    sample_proto_header(&header);
    return header;
}

inline std::string sample_proto_transaction(ByteView rlp_tx) {
    return std::string{byte_view_to_string_view(rlp_tx)};
}

inline std::string sample_proto_tx0() {
    Bytes rlp_tx0{};
    rlp::encode(rlp_tx0, sample_tx0());
    return sample_proto_transaction(rlp_tx0);
}

inline std::string sample_proto_tx1() {
    Bytes rlp_tx1{};
    rlp::encode(rlp_tx1, sample_tx1());
    return sample_proto_transaction(rlp_tx1);
}

inline void sample_proto_ommer(proto::Header* header) {
    header->set_allocated_parent_hash(rpc::h256_from_bytes32(kSampleOmmerParentHash).release());
    header->set_allocated_ommer_hash(rpc::h256_from_bytes32(kEmptyListHash).release());
    header->set_allocated_coinbase(rpc::h160_from_address(kSampleOmmerBeneficiary).release());
    header->set_allocated_state_root(rpc::h256_from_bytes32(kSampleOmmerStateRoot).release());
    header->set_allocated_transaction_hash(rpc::h256_from_bytes32(kEmptyRoot).release());
    header->set_allocated_receipt_root(rpc::h256_from_bytes32(kEmptyRoot).release());
    header->set_allocated_difficulty(rpc::h256_from_uint256(kSampleOmmerDifficulty).release());
    header->set_block_number(kSampleOmmerBlockNum);
    header->set_gas_limit(kSampleOmmerGasLimit);
    header->set_gas_used(kSampleOmmerGasUsed);
    header->set_timestamp(kSampleOmmerTimestamp);
    header->set_allocated_prev_randao(rpc::h256_from_bytes32(kSampleOmmerPrevRandao).release());
    header->set_nonce(endian::load_big_u64(kSampleOmmerNonce.data()));
}

inline void sample_proto_withdrawal(::types::Withdrawal* withdrawal, const Withdrawal& w) {
    withdrawal->set_index(w.index);
    withdrawal->set_validator_index(w.validator_index);
    withdrawal->set_allocated_address(rpc::h160_from_address(w.address).release());
    withdrawal->set_amount(w.amount);
}

inline void sample_proto_body(proto::BlockBody* body) {
    body->set_block_number(kSampleBlockNum);
    body->set_allocated_block_hash(rpc::h256_from_bytes32(kSampleBlockHash).release());

    body->add_transactions(sample_proto_tx0());
    body->add_transactions(sample_proto_tx1());
    sample_proto_ommer(body->add_uncles());
    sample_proto_withdrawal(body->add_withdrawals(), kSampleWithdrawal0);
    sample_proto_withdrawal(body->add_withdrawals(), kSampleWithdrawal1);
    sample_proto_withdrawal(body->add_withdrawals(), kSampleWithdrawal2);
    sample_proto_withdrawal(body->add_withdrawals(), kSampleWithdrawal3);
}

inline void sample_proto_block(proto::Block* block) {
    sample_proto_header(block->mutable_header());
    sample_proto_body(block->mutable_body());
}

}  // namespace silkworm::execution::test_util
