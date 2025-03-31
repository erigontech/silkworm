// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "sync_pos.hpp"

#include <algorithm>
#include <iterator>

#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <magic_enum.hpp>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/measure.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/rpc/engine/conversion.hpp>
#include <silkworm/rpc/engine/validation.hpp>
#include <silkworm/rpc/protocol/errors.hpp>

namespace silkworm::chainsync {

namespace asio = boost::asio;
using namespace concurrency::awaitable_wait_for_one;

class PayloadValidationError : public std::logic_error {
  public:
    PayloadValidationError() : std::logic_error("payload validation error, unknown reason") {}

    explicit PayloadValidationError(const std::string& reason) : std::logic_error(reason) {}
};

PoSSync::PoSSync(IBlockExchange& block_exchange, execution::api::Client& exec_client)
    : ChainSync(block_exchange, exec_client) {}

Task<void> PoSSync::async_run() {
    co_await download_blocks();
}

// Wait for blocks arrival from BlockExchange and insert them into ExecutionEngine
Task<void> PoSSync::download_blocks() {
    using namespace std::chrono_literals;
    using ResultQueue = BlockExchange::ResultQueue;
    ResultQueue& downloading_queue = block_exchange_.result_queue();

    auto executor = co_await asio::this_coro::executor;

    // BlockExchange & ChainForkView need a bunch of previous headers to attach the new ones
    const auto last_headers = co_await exec_engine_->get_last_headers(1000);
    block_exchange_.initial_state(last_headers);
    for (const auto& header : last_headers) {
        auto hash = header.hash();
        auto td = co_await exec_engine_->get_td(hash);
        chain_fork_view_.add(header, *td);  // add to cache
    }

    // initialization
    const auto initial_block_progress = co_await exec_engine_->block_progress();
    auto block_progress = initial_block_progress;

    block_exchange_.download_blocks(block_progress, BlockExchange::TargetTracking::kByNewPayloads);

    StopWatch timing(StopWatch::kStart);
    RepeatedMeasure<BlockNum> downloaded_headers(initial_block_progress);
    SILK_INFO << "PoSSync: Waiting for blocks... from=" << initial_block_progress;

    asio::steady_timer timer(executor);

    // main loop
    try {
        while (true) {
            Blocks blocks;

            // wait for a batch of blocks
            bool present = downloading_queue.try_pop(blocks);
            if (!present) {
                // a trick to avoid busy waiting
                timer.expires_after(100ms);
                co_await timer.async_wait(asio::use_awaitable);
                continue;
            }

            // compute head of chain applying fork choice rule
            std::ranges::for_each(blocks, [&, this](const auto& block) {
                block->td = chain_fork_view_.add(block->header);
                block_progress = std::max(block_progress, block->header.number);
            });

            // insert blocks into database
            const auto insert_result{co_await exec_engine_->insert_blocks(to_plain_blocks(blocks))};
            if (!insert_result) {
                SILK_ERROR << "PoSSync: cannot insert " << blocks.size() << " blocks, error=" << insert_result.status;
                continue;
            }

            downloaded_headers.set(block_progress);
            SILK_INFO
                << "PoSSync: Downloading progress: +" << downloaded_headers.delta() << " blocks downloaded, "
                << downloaded_headers.high_res_throughput<seconds_t>() << " headers/secs"
                << ", last=" << downloaded_headers.get()
                << ", lap.duration=" << StopWatch::format(timing.since_start());
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "PoSSync: exiting download_blocks loop exception=" << e.what();
    }
}

void PoSSync::do_sanity_checks(const BlockHeader&, /*const BlockHeader& parent,*/ TotalDifficulty parent_td) {
    auto terminal_total_difficulty = block_exchange_.chain_config().terminal_total_difficulty;

    if (parent_td < terminal_total_difficulty) throw PayloadValidationError("ignoring pre-merge payload");

    // here Geth checks parent.Difficulty().BitLen() > 0 && gptd != nil && gptd.Cmp(ttd) >= 0 todo: understand
    // auto grand_parent_td = exec_engine_.get_header_td(parent.number - 1, parent.parent_hash);
    // if (parent.difficulty != 0 && grand_parent_td && grand_parent_td >= terminal_total_difficulty)
    //    throw PayloadValidationError("ignoring pre-merge parent block");

    // if (pos_header.timestamp <= parent.timestamp) throw PayloadValidationError("invalid timestamp");
    //  here Geth return last_valid = fcu head
}

std::tuple<bool, Hash> PoSSync::has_valid_ancestor(const Hash&) {
    return {true, Hash()};  // todo: implement, return if it is valid or the first valid ancestor
}

Task<rpc::PayloadStatus> PoSSync::new_payload(const rpc::NewPayloadRequest& request, std::chrono::milliseconds timeout) {
    // Implementation of engine_new_payloadVx method
    using namespace execution;
    constexpr evmc::bytes32 kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;
    auto terminal_total_difficulty = block_exchange_.chain_config().terminal_total_difficulty;
    const auto no_latest_valid_hash = std::nullopt;

    const auto& payload{request.execution_payload};
    try {
        // Make the execution full block from the block payload
        auto block = rpc::engine::block_from_execution_payload(payload);  // as per the EngineAPI spec

        // Handle version-specific fields
        if (request.parent_beacon_block_root) {
            block->header.parent_beacon_block_root = request.parent_beacon_block_root;
        }

        // Validations
        if (const auto res{rpc::engine::validate_blob_hashes(*block, request.expected_blob_versioned_hashes)}; !res) {
            co_return rpc::PayloadStatus{rpc::PayloadStatus::kInvalidStr, no_latest_valid_hash, res.error()};
        }

        Hash block_hash = block->header.hash();
        if (payload.block_hash != block_hash) {
            co_return rpc::PayloadStatus::kInvalidBlockHash;
        }
        SILK_TRACE << "PoSSync: new_payload block_hash=" << block_hash << " block_num: " << block->header.number;

        if (active_chain_validations_ > 0) {
            SILK_INFO << "PoSSync: new_payload block_hash=" << block_hash << " block_num: " << block->header.number
                      << " <- reply SYNCING";
            co_return rpc::PayloadStatus::kSyncing;
        }

        auto [valid, last_valid] = has_valid_ancestor(block_hash);
        if (!valid) co_return rpc::PayloadStatus{rpc::PayloadStatus::kInvalidStr, last_valid, "bad ancestor"};

        // Find attaching point using chain fork view first to avoid remote access to execution
        auto parent_td = chain_fork_view_.get_total_difficulty(block->header.number - 1, block->header.parent_hash);
        if (!parent_td) {
            // if not found, try to get it from the execution engine
            const auto parent = co_await exec_engine_->get_header(block->header.parent_hash);
            if (!parent) {
                SILK_TRACE << "PoSSync: new_payload parent=" << Hash(block->header.parent_hash) << " NOT found, extend the chain";
                // send payload to the block exchange to extend the chain up to it
                block_exchange_.new_target_block(std::move(block));
                co_return rpc::PayloadStatus::kSyncing;
            }
            SILK_TRACE << "PoSSync: new_payload parent=" << Hash(block->header.parent_hash) << " found, add to chain fork";
            // if found, add it to the chain_fork_view_ and calc total difficulty
            parent_td = co_await exec_engine_->get_td(block->header.parent_hash);
            // TODO(canepat) either remove caching here or use a distinct cache (the same ChainForkView eats on itself)
            chain_fork_view_.add(*parent, *parent_td);
        }  // maybe we can simplify the code above returning kSyncing if parent_td is not found on  chain_fork_view

        // do sanity checks
        do_sanity_checks(block->header, /*parent,*/ *parent_td);

        // block_exchange_.insert(block);  // todo: implement, like HeaderChain::initial_status + BodySequence::add_to_announcements

        // insert the new block
        std::vector<std::shared_ptr<Block>> blocks{block};
        const auto insert_result{co_await exec_engine_->insert_blocks(blocks)};
        if (!insert_result) {
            SILK_ERROR << "PoSSync: cannot insert " << blocks.size() << " blocks, error=" << insert_result.status;
            co_return rpc::PayloadStatus::kSyncing;
        }

        const auto block_num = co_await exec_engine_->get_header_hash_number(block_hash);
        if (!block_num) {
            co_return rpc::PayloadStatus::kAccepted;
        }
        SILK_TRACE << "PoSSync: new_payload block_num=" << *block_num << " inserted";

        // NOTE: from here the method execution can be cancelled
        ++active_chain_validations_;
        const auto verification = co_await (exec_engine_->validate_chain({*block_num, block_hash}) || concurrency::timeout(timeout));
        --active_chain_validations_;

        if (std::holds_alternative<execution::api::ValidChain>(verification)) {
            // VALID
            SILK_INFO << "PoSSync: new_payload VALID current_head=" << std::get<execution::api::ValidChain>(verification).current_head.hash;
            co_return rpc::PayloadStatus{.status = rpc::PayloadStatus::kValidStr, .latest_valid_hash = block_hash};
        } else if (std::holds_alternative<execution::api::InvalidChain>(verification)) {
            // INVALID
            const auto invalid_chain = std::get<execution::api::InvalidChain>(verification);
            auto unwind_point_td = chain_fork_view_.get_total_difficulty(invalid_chain.unwind_point.hash);
            Hash latest_valid_hash = unwind_point_td < terminal_total_difficulty
                                         ? kZeroHash
                                         : invalid_chain.unwind_point.hash;
            SILK_INFO << "PoSSync: new_payload INVALID latest_valid_hash=" << latest_valid_hash;
            co_return rpc::PayloadStatus{.status = rpc::PayloadStatus::kInvalidStr, .latest_valid_hash = latest_valid_hash};
        } else {
            // ERROR
            const auto validation_error = std::get<execution::api::ValidationError>(verification);
            SILK_INFO << "PoSSync: new_payload INVALID latest_valid_hash=" << validation_error.latest_valid_head.hash
                      << " validation_error=" << validation_error.error;
            co_return rpc::PayloadStatus{rpc::PayloadStatus::kInvalidStr, no_latest_valid_hash, "unknown execution error"};
        }

    } catch (const PayloadValidationError& e) {
        SILK_INFO << "PoSSync: new_payload payload validation error: " << e.what();
        co_return rpc::PayloadStatus{rpc::PayloadStatus::kInvalidStr, no_latest_valid_hash, e.what()};
    } catch (const concurrency::TimeoutExpiredError& tee) {
        SILK_WARN << "PoSSync: new_payload timeout expired: " << tee.what();
        co_return rpc::PayloadStatus::kSyncing;
    } catch (const boost::system::system_error& e) {
        SILK_ERROR << "PoSSync: error processing payload: " << e.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "PoSSync: unexpected error processing payload: " << e.what();
        throw;
    }
}

Task<rpc::ForkChoiceUpdatedReply> PoSSync::fork_choice_updated(const rpc::ForkChoiceUpdatedRequest& request, std::chrono::milliseconds timeout) {
    // Implementation of engine_forkchoiceUpdatedVx method
    using namespace execution;
    constexpr evmc::bytes32 kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;
    auto terminal_total_difficulty = block_exchange_.chain_config().terminal_total_difficulty;
    auto no_latest_valid_hash = std::nullopt;

    const auto& state{request.fork_choice_state};
    const auto& attributes{request.payload_attributes};
    try {
        if (!state.head_block_hash) {
            co_return rpc::ForkChoiceUpdatedReply{{rpc::PayloadStatus::kInvalidStr, no_latest_valid_hash, "invalid head block hash"}};
        }
        SILK_INFO << "PoSSync: fork_choice_update head_block_hash=" << Hash(state.head_block_hash)
                  << " safe_block_hash=" << Hash(state.safe_block_hash) << " finalized_block_hash=" << Hash(state.finalized_block_hash);

        Hash head_header_hash = state.head_block_hash;
        const auto head_header = co_await exec_engine_->get_header(head_header_hash);  // todo: decide whether to use chain_fork_view_ cache instead
        if (!head_header) {
            auto [valid, last_valid] = has_valid_ancestor(head_header_hash);
            if (!valid) co_return rpc::ForkChoiceUpdatedReply{{rpc::PayloadStatus::kInvalidStr, last_valid, "bad ancestor"}};

            SILK_INFO << "PoSSync: fork_choice_update head header not found => SYNCING";
            // send payload to the block exchange to extend the chain up to it
            // block_exchange_.new_target_block(head_header_hash);  // todo: implement this!
            co_return rpc::ForkChoiceUpdatedReply{rpc::PayloadStatus::kSyncing};
        }

        // BlockId head{head_header->number, head_header_hash};

        const auto parent = co_await exec_engine_->get_header(head_header->parent_hash);  // todo: decide whether to use chain_fork_view_ cache instead
        if (!parent) {
            SILK_INFO << "PoSSync: fork_choice_update parent header not found => SYNCING";
            co_return rpc::ForkChoiceUpdatedReply{rpc::PayloadStatus::kSyncing};
        }
        auto parent_td = chain_fork_view_.get_total_difficulty(head_header->number - 1, head_header->parent_hash);
        if (!parent_td) {
            SILK_INFO << "PoSSync: fork_choice_update TD not found for parent block number=" << (head_header->number - 1)
                      << " hash=" << Hash(head_header->parent_hash) << " => SYNCING";
            co_return rpc::ForkChoiceUpdatedReply{rpc::PayloadStatus::kSyncing};
        }

        do_sanity_checks(*head_header, /**parent,*/ *parent_td);

        // NOTE: from here the method execution can be cancelled
        ++active_chain_validations_;
        const auto verification = co_await (exec_engine_->validate_chain({head_header->number, head_header_hash}) ||
                                            concurrency::timeout(timeout));  // does nothing if previously validated
        --active_chain_validations_;

        if (std::holds_alternative<execution::api::InvalidChain>(verification)) {
            // INVALID
            auto invalid_chain = std::get<execution::api::InvalidChain>(verification);
            auto unwind_point_td = chain_fork_view_.get_total_difficulty(invalid_chain.unwind_point.hash);
            Hash latest_valid_hash = unwind_point_td < terminal_total_difficulty
                                         ? kZeroHash
                                         : invalid_chain.unwind_point.hash;
            SILK_INFO << "PoSSync: fork_choice_update INVALID latest_valid_hash=" << latest_valid_hash;
            co_return rpc::ForkChoiceUpdatedReply{{rpc::PayloadStatus::kInvalidStr, latest_valid_hash}};
        } else if (std::holds_alternative<execution::api::ValidationError>(verification)) {
            // ERROR
            const auto validation_error = std::get<execution::api::ValidationError>(verification);
            SILK_INFO << "PoSSync: fork_choice_update INVALID latest_valid_hash=" << validation_error.latest_valid_head.hash
                      << " validation_error=" << validation_error.error;
            co_return rpc::ForkChoiceUpdatedReply{{rpc::PayloadStatus::kInvalidStr, no_latest_valid_hash, "unknown execution error"}};
        }

        // VALID
        const std::optional<Hash> finalized_block_hash =
            state.finalized_block_hash != kZeroHash ? std::optional<Hash>{state.finalized_block_hash} : std::nullopt;
        const std::optional<Hash> safe_block_hash =
            state.safe_block_hash != kZeroHash ? std::optional<Hash>{state.safe_block_hash} : std::nullopt;

        api::ForkChoice fork_choice_point{
            .head_block_hash = state.head_block_hash,
            .finalized_block_hash = finalized_block_hash,
            .safe_block_hash = safe_block_hash,
        };
        const auto result = co_await (exec_engine_->update_fork_choice(fork_choice_point) || concurrency::timeout(timeout));
        ensure(std::holds_alternative<api::ForkChoiceResult>(result), "PoSSync: unexpected awaitable operators outcome");
        const auto fcu_result{std::get<api::ForkChoiceResult>(result)};
        SILK_INFO
            << "PoSSync: fork_choice_update " << (fcu_result ? "OK" : "KO")
            << " latest_valid_hash=" << (fcu_result ? Hash(state.head_block_hash).to_hex() : fcu_result.latest_valid_head.to_hex())
            << " current_head=" << fcu_result.latest_valid_head << " current_block_num=";
        if (!fcu_result) {
            // at the moment application doesn't carry information to disambiguate between invalid head and
            // finalized_block_hash not found, so we need additional calls:

            if (finalized_block_hash) {
                auto is_canonical = co_await exec_engine_->is_canonical_hash(*finalized_block_hash);
                if (!is_canonical) throw boost::system::system_error{rpc::to_system_code(rpc::ErrorCode::kInvalidForkChoiceState)};
            }
            if (safe_block_hash) {
                auto is_canonical = co_await exec_engine_->is_canonical_hash(*safe_block_hash);
                if (!is_canonical) throw boost::system::system_error{rpc::to_system_code(rpc::ErrorCode::kInvalidForkChoiceState)};
            }

            co_return rpc::ForkChoiceUpdatedReply{{rpc::PayloadStatus::kInvalidStr, fcu_result.latest_valid_head, "invalid fork choice update"}};
        }

        std::optional<uint64_t> build_process_id;
        if (attributes) {
            // payload build process
            if (attributes->timestamp <= head_header->timestamp) {
                throw boost::system::system_error{rpc::to_system_code(rpc::ErrorCode::kInvalidPayloadAttributes)};
                // in this case spec states that forkchoiceState update MUST NOT be rolled back
            }

            // build_process_id = exec_engine_.build_payload(head_header_hash, attributes);
        }

        co_return rpc::ForkChoiceUpdatedReply{{rpc::PayloadStatus::kValidStr, state.head_block_hash}, build_process_id};

    } catch (const concurrency::TimeoutExpiredError& tee) {
        SILK_INFO << "PoSSync: new_payload timeout expired: " << tee.what();
        co_return rpc::ForkChoiceUpdatedReply{rpc::PayloadStatus::kSyncing};
    } catch (const boost::system::system_error& e) {
        SILK_ERROR << "PoSSync: error processing fork-choice: " << e.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "PoSSync: unexpected error processing fork-choice: " << e.what();
        throw;
    }
}

Task<rpc::ExecutionPayloadAndValue> PoSSync::get_payload(uint64_t /*payload_id*/, std::chrono::milliseconds /*timeout*/) {
    // Implementation of engine_getPayloadVx method
    ensure_invariant(false, "get_payload not implemented");
    co_return rpc::ExecutionPayloadAndValue{};
}

Task<rpc::ExecutionPayloadBodies> PoSSync::get_payload_bodies_by_hash(const std::vector<Hash>& block_hashes, std::chrono::milliseconds /*timeout*/) {
    rpc::ExecutionPayloadBodies payload_bodies;
    payload_bodies.resize(block_hashes.size());
    for (const auto& bh : block_hashes) {
        const auto block_body{co_await exec_engine_->get_body(bh)};
        if (block_body) {
            std::vector<Bytes> rlp_txs;
            rlp_txs.reserve(block_body->transactions.size());
            for (const auto& transaction : block_body->transactions) {
                Bytes tx_rlp;
                rlp::encode(tx_rlp, transaction);
                rlp_txs.emplace_back(tx_rlp.data(), tx_rlp.size());
            }
            rpc::ExecutionPayloadBody payload_body{
                .transactions = std::move(rlp_txs),
                .withdrawals = block_body->withdrawals,
            };
            payload_bodies.push_back(payload_body);
        } else {
            // Add an empty payload anyway because we must respond w/ one payload for each hash
            payload_bodies.emplace_back();
        }
    }
    co_return payload_bodies;
}

Task<rpc::ExecutionPayloadBodies> PoSSync::get_payload_bodies_by_range(BlockNum start, uint64_t count, std::chrono::milliseconds /*timeout*/) {
    rpc::ExecutionPayloadBodies payload_bodies;
    payload_bodies.resize(count);
    for (BlockNum block_num = start; block_num < start + count; ++block_num) {
        const auto block_body{co_await exec_engine_->get_body(block_num)};
        if (block_body) {
            std::vector<Bytes> rlp_txs;
            rlp_txs.reserve(block_body->transactions.size());
            for (const auto& transaction : block_body->transactions) {
                Bytes tx_rlp;
                rlp::encode(tx_rlp, transaction);
                rlp_txs.emplace_back(tx_rlp.data(), tx_rlp.size());
            }
            rpc::ExecutionPayloadBody payload_body{
                .transactions = std::move(rlp_txs),
                .withdrawals = block_body->withdrawals,
            };
            payload_bodies.push_back(payload_body);
        } else {
            // Add an empty payload anyway because we must respond w/ one payload for each hash
            payload_bodies.emplace_back();
        }
    }
    co_return payload_bodies;
}

}  // namespace silkworm::chainsync