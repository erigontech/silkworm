// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "server_calls.hpp"

#include <stdexcept>

#include <silkworm/infra/grpc/common/conversion.hpp>

#include "endpoint/assembly.hpp"
#include "endpoint/checkers.hpp"
#include "endpoint/getters.hpp"
#include "endpoint/insertion.hpp"
#include "endpoint/range.hpp"
#include "endpoint/status.hpp"
#include "endpoint/validation.hpp"

namespace silkworm::execution::grpc::server {

Task<void> InsertBlocksCall::operator()(api::DirectService& service) {
    proto::InsertionResult reply;
    ::grpc::Status status;
    try {
        const auto blocks{blocks_from_insertion_request(request_)};
        if (blocks) {
            const api::InsertionResult result = co_await service.insert_blocks(*blocks);
            reply = response_from_insertion_result(result);
        } else {
            reply.set_result(proto_from_execution_status(api::ExecutionStatus::kBadBlock));
        }
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> ValidateChainCall::operator()(api::DirectService& service) {
    proto::ValidationReceipt reply;
    ::grpc::Status status;
    try {
        const auto block_id = block_id_from_request(request_);
        const api::ValidationResult result = co_await service.validate_chain(block_id);
        reply = response_from_validation_result(result);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> UpdateForkChoiceCall::operator()(api::DirectService& service) {
    proto::ForkChoiceReceipt reply;
    ::grpc::Status status;
    try {
        const auto fork_choice{fork_choice_from_request(request_)};
        const api::ForkChoiceResult result = co_await service.update_fork_choice(fork_choice);
        reply = response_from_fork_choice_result(result);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> AssembleBlockCall::operator()(api::DirectService& service) {
    proto::AssembleBlockResponse reply;
    ::grpc::Status status;
    try {
        const auto block{block_from_assemble_request(request_)};
        const api::AssembleBlockResult result = co_await service.assemble_block(block);
        reply = response_from_assemble_result(result);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> GetAssembledBlockCall::operator()(api::DirectService& service) {
    proto::GetAssembledBlockResponse reply;
    ::grpc::Status status;
    try {
        const auto payload_id{get_assembled_request_from_payload_id(request_)};
        const api::AssembledBlockResult result = co_await service.get_assembled_block(payload_id);
        reply = response_from_get_assembled_result(result);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> CurrentHeaderCall::operator()(api::DirectService& service) {
    proto::GetHeaderResponse reply;
    ::grpc::Status status;
    try {
        const std::optional<BlockHeader> result = co_await service.current_header();
        reply = response_from_header(result);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> GetTDCall::operator()(api::DirectService& service) {
    proto::GetTDResponse reply;
    ::grpc::Status status;
    try {
        const auto block_num_or_hash{block_num_or_hash_from_request(request_)};
        const std::optional<TotalDifficulty> result = co_await service.get_td(block_num_or_hash);
        reply = response_from_total_difficulty(result);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> GetHeaderCall::operator()(api::DirectService& service) {
    proto::GetHeaderResponse reply;
    ::grpc::Status status;
    try {
        const auto block_num_or_hash{block_num_or_hash_from_request(request_)};
        const std::optional<BlockHeader> result = co_await service.get_header(block_num_or_hash);
        reply = response_from_header(result);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> GetBodyCall::operator()(api::DirectService& service) {
    proto::GetBodyResponse reply;
    ::grpc::Status status;
    try {
        const auto block_num_or_hash{block_num_or_hash_from_request(request_)};
        const std::optional<BlockBody> result = co_await service.get_body(block_num_or_hash);
        const std::optional<BlockHeader> header = co_await service.get_header(block_num_or_hash);
        Hash block_hash{};
        BlockNum block_num{0};
        if (std::holds_alternative<Hash>(block_num_or_hash)) {
            block_hash = std::get<Hash>(block_num_or_hash);
            if (header) {
                block_num = header->number;
            }
        } else {
            block_num = std::get<BlockNum>(block_num_or_hash);
            if (header) {
                block_hash = header->hash();
            }
        }
        reply = response_from_body(result, block_hash, block_num);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> HasBlockCall::operator()(api::DirectService& service) {
    proto::HasBlockResponse reply;
    ::grpc::Status status;
    try {
        const auto block_num_or_hash{block_num_or_hash_from_request(request_)};
        const bool has_block = co_await service.has_block(block_num_or_hash);
        reply.set_has_block(has_block);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> GetBodiesByRangeCall::operator()(api::DirectService& service) {
    proto::GetBodiesBatchResponse reply;
    ::grpc::Status status;
    try {
        const auto block_num_range{block_num_range_from_request(request_)};
        const auto block_bodies = co_await service.get_bodies_by_range(block_num_range);
        reply = response_from_bodies(block_bodies);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> GetBodiesByHashesCall::operator()(api::DirectService& service) {
    proto::GetBodiesBatchResponse reply;
    ::grpc::Status status;
    try {
        const auto block_hashes{block_hashes_from_request(request_)};
        const auto block_bodies = co_await service.get_bodies_by_hashes(block_hashes);
        reply = response_from_bodies(block_bodies);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> IsCanonicalHashCall::operator()(api::DirectService& service) {
    proto::IsCanonicalResponse reply;
    ::grpc::Status status;
    try {
        const auto block_hash{rpc::bytes32_from_h256(request_)};
        const bool is_canonical = co_await service.is_canonical_hash(block_hash);
        reply.set_canonical(is_canonical);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> GetHeaderHashNumberCall::operator()(api::DirectService& service) {
    proto::GetHeaderHashNumberResponse reply;
    ::grpc::Status status;
    try {
        const auto block_hash{rpc::bytes32_from_h256(request_)};
        const auto block_num = co_await service.get_header_hash_number(block_hash);
        reply = response_from_block_num(block_num);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> GetForkChoiceCall::operator()(api::DirectService& service) {
    proto::ForkChoice reply;
    ::grpc::Status status;
    try {
        const auto fork_choice = co_await service.get_fork_choice();
        reply = response_from_fork_choice(fork_choice);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> ReadyCall::operator()(api::DirectService& service) {
    proto::ReadyResponse reply;
    ::grpc::Status status;
    try {
        const bool is_ready = co_await service.ready();
        reply.set_ready(is_ready);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

Task<void> FrozenBlocksCall::operator()(api::DirectService& service) {
    proto::FrozenBlocksResponse reply;
    ::grpc::Status status;
    try {
        const uint64_t num_frozen_blocks = co_await service.frozen_blocks();
        reply.set_frozen_blocks(num_frozen_blocks);
        status = ::grpc::Status::OK;
    } catch (const std::exception& e) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, e.what()};
    }
    co_await agrpc::finish(responder_, reply, status);
}

}  // namespace silkworm::execution::grpc::server
