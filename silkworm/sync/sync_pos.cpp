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

#include "sync_pos.hpp"

#include <iterator>

#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <magic_enum.hpp>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/core/protocol/validation.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/measure.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/silkrpc/protocol/errors.hpp>

namespace silkworm::chainsync {

using namespace boost::asio;

class PayloadValidationError : public std::logic_error {
  public:
    PayloadValidationError() : std::logic_error("payload validation error, unknown reason") {}

    explicit PayloadValidationError(const std::string& reason) : std::logic_error(reason) {}
};

PoSSync::PoSSync(BlockExchange& be, execution::Client& ee) : ChainSync(be, ee) {}

awaitable<void> PoSSync::async_run() {
    co_await download_blocks();
}

// Wait for blocks arrival from BlockExchange and insert them into ExecutionEngine
awaitable<void> PoSSync::download_blocks() {
    using namespace std::chrono_literals;
    using ResultQueue = BlockExchange::ResultQueue;
    ResultQueue& downloading_queue = block_exchange_.result_queue();

    auto executor = co_await asio::this_coro::executor;

    // BlockExchange & ChainForkView need a bunch of previous headers to attach the new ones
    auto last_headers = co_await exec_engine_.get_last_headers(1000);
    block_exchange_.initial_state(last_headers);
    as_range::for_each(last_headers, [&, this](const auto& header) -> awaitable<void> {
        auto hash = header.hash();
        auto td = co_await exec_engine_.get_header_td(hash, std::nullopt);
        chain_fork_view_.add(header, *td);  // add to cache
    });

    // initialization
    auto initial_block_progress = co_await exec_engine_.block_progress();
    auto block_progress = initial_block_progress;

    block_exchange_.download_blocks(block_progress, BlockExchange::Target_Tracking::kByNewPayloads);

    StopWatch timing(StopWatch::kStart);
    RepeatedMeasure<BlockNum> downloaded_headers(initial_block_progress);
    log::Info() << "[PoSSync] Waiting for blocks... from=" << initial_block_progress;

    asio::steady_timer timer(executor);

    // main loop
    while (true) {
        Blocks blocks;

        // wait for a batch of blocks
        bool present = downloading_queue.try_pop(blocks);
        if (!present) {
            timer.expires_after(100ms);
            co_await timer.async_wait(asio::use_awaitable);  // a trick to avoid busy waiting, to replace with an awaitable queue
            continue;
        }

        // compute head of chain applying fork choice rule
        as_range::for_each(blocks, [&, this](const auto& block) {
            block->td = chain_fork_view_.add(block->header);
            block_progress = std::max(block_progress, block->header.number);
        });

        // insert blocks into database
        co_await exec_engine_.insert_blocks(to_plain_blocks(blocks));

        downloaded_headers.set(block_progress);
        log::Info() << "[PoSSync] Downloading progress: +" << downloaded_headers.delta() << " blocks downloaded, "
                    << downloaded_headers.high_res_throughput<seconds_t>() << " headers/secs"
                    << ", last=" << downloaded_headers.get()
                    << ", head=" << chain_fork_view_.head_height()
                    << ", lap.duration=" << StopWatch::format(timing.since_start());
    }
}

// Convert an ExecutionPayload to a Block as per Engine API spec
std::shared_ptr<Block> PoSSync::make_execution_block(const rpc::ExecutionPayload& payload) {
    std::shared_ptr<Block> block = std::make_shared<Block>();
    BlockHeader& header = block->header;

    header.number = payload.number;
    header.timestamp = payload.timestamp;
    header.parent_hash = payload.parent_hash;
    header.state_root = payload.state_root;
    header.receipts_root = payload.receipts_root;
    header.logs_bloom = payload.logs_bloom;
    header.gas_used = payload.gas_used;
    header.gas_limit = payload.gas_limit;
    header.timestamp = payload.timestamp;
    header.extra_data = payload.extra_data;
    header.base_fee_per_gas = payload.base_fee;
    header.beneficiary = payload.suggested_fee_recipient;

    for (const auto& rlp_encoded_tx : payload.transactions) {
        ByteView rlp_encoded_tx_view{rlp_encoded_tx};
        Transaction tx;
        auto decoding_result = rlp::decode_transaction(rlp_encoded_tx_view, tx, rlp::Eip2718Wrapping::kBoth);
        if (!decoding_result) {
            std::string reason{magic_enum::enum_name<DecodingError>(decoding_result.error())};
            throw PayloadValidationError("tx rlp decoding error: " + reason);
        }
        block->transactions.push_back(tx);
    }
    header.transactions_root = protocol::compute_transaction_root(*block);

    // as per EIP-4895
    if (payload.withdrawals) {
        block->withdrawals = std::vector<Withdrawal>{};
        block->withdrawals->reserve(payload.withdrawals->size());
        std::copy(payload.withdrawals->begin(), payload.withdrawals->end(), std::back_inserter(*block->withdrawals));
        header.withdrawals_root = protocol::compute_withdrawals_root(*block);
    }

    // as per EIP-3675
    header.ommers_hash = kEmptyListHash;  // = Keccak256(RLP([]))
    header.difficulty = 0;
    header.nonce = {0, 0, 0, 0, 0, 0, 0, 0};
    block->ommers = {};  // RLP([]) = 0xc0

    // as per EIP-4399
    header.prev_randao = payload.prev_randao;

    return block;
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

auto PoSSync::has_valid_ancestor(const Hash&) -> std::tuple<bool, Hash> {
    return {true, Hash()};  // todo: implement, return if it is valid or the first valid ancestor
}

auto PoSSync::new_payload(const rpc::ExecutionPayload& payload) -> asio::awaitable<rpc::PayloadStatus> {
    // Implementation of engine_new_payloadVx method
    using namespace execution;
    constexpr evmc::bytes32 kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;
    auto terminal_total_difficulty = block_exchange_.chain_config().terminal_total_difficulty;
    auto no_latest_valid_hash = std::nullopt;

    try {
        // get to execution block & do some checks
        auto block = make_execution_block(payload);  // as per the EngineAPI spec

        Hash block_hash = block->header.hash();
        if (payload.block_hash != block_hash) co_return rpc::PayloadStatus::InvalidBlockHash;
        log::Info() << "[PoSSync] new_payload block_hash=" << block_hash << " block_number: " << block->header.number;

        auto [valid, last_valid] = has_valid_ancestor(block_hash);
        if (!valid) co_return rpc::PayloadStatus{rpc::PayloadStatus::kInvalid, last_valid, "bad ancestor"};

        // find attaching point using chain_fork_view_ first to avoid remote access to execution
        auto parent_td = chain_fork_view_.get_total_difficulty(block->header.number - 1, block->header.parent_hash);
        if (!parent_td) {
            // if not found, try to get it from the execution engine
            auto parent = co_await exec_engine_.get_header(block->header.number - 1, block->header.parent_hash);
            if (!parent) {
                log::Trace() << "[PoSSync] new_payload parent=" << to_hex(block->header.parent_hash) << " NOT found, extend the chain";
                // send payload to the block exchange to extend the chain up to it
                block_exchange_.new_target_block(std::move(block));
                co_return rpc::PayloadStatus::Syncing;
            }
            log::Trace() << "[PoSSync] new_payload parent=" << to_hex(block->header.parent_hash) << " found, add to chain fork";
            // if found, add it to the chain_fork_view_ and calc total difficulty
            parent_td = co_await exec_engine_.get_header_td(block->header.parent_hash, block->header.number - 1);
            chain_fork_view_.add(*parent, *parent_td);
        }  // maybe we can simplify the code above returning Syncing if parent_td is not found on  chain_fork_view

        // do sanity checks
        do_sanity_checks(block->header, /*parent,*/ *parent_td);

        // block_exchange_.insert(block);  // todo: implement, like HeaderChain::initial_status + BodySequence::add_to_announcements

        // insert the new block
        std::vector<std::shared_ptr<Block>> blocks{block};
        co_await exec_engine_.insert_blocks(blocks);
        // auto inserted = co_await exec_engine_.insert_block(block); this is not working due to proto interface limitations
        const auto inserted = co_await exec_engine_.get_block_num(block_hash);
        if (!inserted) {
            co_return rpc::PayloadStatus::Accepted;
        }
        log::Trace() << "[PoSSync] new_payload block_number=" << *inserted << " inserted";

        // NOTE: from here the method execution can be cancelled
        auto verification = co_await exec_engine_.validate_chain(block_hash);

        if (std::holds_alternative<ValidChain>(verification)) {
            // VALID
            log::Info() << "[PoSSync] new_payload VALID current_head=" << std::get<ValidChain>(verification).current_head;
            co_return rpc::PayloadStatus{.status = rpc::PayloadStatus::kValid, .latest_valid_hash = block_hash};
        } else if (std::holds_alternative<InvalidChain>(verification)) {
            // INVALID
            const auto invalid_chain = std::get<InvalidChain>(verification);
            // auto latest_valid_height = sync_wait(in(exec_engine_), exec_engine_.get_block_num(invalid_chain.latest_valid_head));
            auto unwind_point_td = chain_fork_view_.get_total_difficulty(invalid_chain.latest_valid_head);
            Hash latest_valid_hash = unwind_point_td < terminal_total_difficulty
                                         ? kZeroHash
                                         : invalid_chain.latest_valid_head;
            log::Info() << "[PoSSync] new_payload INVALID latest_valid_hash=" << latest_valid_hash;
            co_return rpc::PayloadStatus{.status = rpc::PayloadStatus::kInvalid, .latest_valid_hash = latest_valid_hash};
        } else {
            // ERROR
            const auto validation_error = std::get<ValidationError>(verification);
            log::Info() << "[PoSSync] new_payload INVALID latest_valid_hash=" << validation_error.latest_valid_head
                        << " missing_block=" << validation_error.missing_block;
            co_return rpc::PayloadStatus{rpc::PayloadStatus::kInvalid, no_latest_valid_hash, "unknown execution error"};
        }

    } catch (const PayloadValidationError& e) {
        log::Info() << "[PoSSync] new_payload payload validation error: " << e.what();
        co_return rpc::PayloadStatus{rpc::PayloadStatus::kInvalid, no_latest_valid_hash, e.what()};
    } catch (const boost::system::system_error& e) {
        log::Error() << "PoSSync: error processing payload: " << e.what();
        throw;
    } catch (const std::exception& e) {
        log::Error() << "PoSSync: unexpected error processing payload: " << e.what();
        throw;
    }
}

auto PoSSync::fork_choice_update(const rpc::ForkChoiceState& state,
                                 const std::optional<rpc::PayloadAttributes>& attributes) -> asio::awaitable<rpc::ForkChoiceUpdatedReply> {
    // Implementation of engine_forkchoiceUpdatedVx method
    using namespace execution;
    constexpr evmc::bytes32 kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;
    auto terminal_total_difficulty = block_exchange_.chain_config().terminal_total_difficulty;
    auto no_latest_valid_hash = std::nullopt;
    auto no_payload_id = std::nullopt;
    try {
        if (!state.head_block_hash) {
            co_return rpc::ForkChoiceUpdatedReply{{rpc::PayloadStatus::kInvalid, no_latest_valid_hash, "invalid head block hash"}, no_payload_id};
        }
        log::Info() << "[PoSSync] fork_choice_update head_block_hash=" << to_hex(state.head_block_hash)
                    << " safe_block_hash=" << to_hex(state.safe_block_hash) << " finalized_block_hash=" << to_hex(state.finalized_block_hash);

        Hash head_header_hash = state.head_block_hash;
        auto head_header = co_await exec_engine_.get_header(head_header_hash);  // todo: decide whether to use chain_fork_view_ cache instead
        if (!head_header) {
            auto [valid, last_valid] = has_valid_ancestor(head_header_hash);
            if (!valid) co_return rpc::ForkChoiceUpdatedReply{{rpc::PayloadStatus::kInvalid, last_valid, "bad ancestor"}, no_payload_id};

            log::Info() << "[PoSSync] fork_choice_update head header not found => SYNCING";
            // send payload to the block exchange to extend the chain up to it
            // block_exchange_.new_target_block(head_header_hash);  // todo: implement this!
            co_return rpc::ForkChoiceUpdatedReply{rpc::PayloadStatus::Syncing, no_payload_id};
        }

        // BlockId head{head_header->number, head_header_hash};

        auto parent = co_await exec_engine_.get_header(head_header->parent_hash);  // todo: decide whether to use chain_fork_view_ cache instead
        if (!parent) {
            log::Info() << "[PoSSync] fork_choice_update parent header not found => SYNCING";
            co_return rpc::ForkChoiceUpdatedReply{rpc::PayloadStatus::Syncing, no_payload_id};
        }
        auto parent_td = chain_fork_view_.get_total_difficulty(head_header->number - 1, head_header->parent_hash);
        if (!parent_td) {
            log::Info() << "[PoSSync] fork_choice_update TD not found for parent block number=" << (head_header->number - 1)
                        << " hash=" << to_hex(head_header->parent_hash) << " => SYNCING";
            co_return rpc::ForkChoiceUpdatedReply{rpc::PayloadStatus::Syncing, no_payload_id};
        }

        do_sanity_checks(*head_header, /**parent,*/ *parent_td);

        // NOTE: from here the method execution can be cancelled
        auto verification = co_await exec_engine_.validate_chain(head_header_hash);  // does nothing if previously validated

        if (std::holds_alternative<InvalidChain>(verification)) {
            // INVALID
            auto invalid_chain = std::get<InvalidChain>(verification);
            auto unwind_point_td = chain_fork_view_.get_total_difficulty(invalid_chain.latest_valid_head);
            Hash latest_valid_hash = unwind_point_td < terminal_total_difficulty
                                         ? kZeroHash
                                         : invalid_chain.latest_valid_head;
            log::Info() << "[PoSSync] fork_choice_update INVALID latest_valid_hash=" << latest_valid_hash;
            co_return rpc::ForkChoiceUpdatedReply{{rpc::PayloadStatus::kInvalid, latest_valid_hash}, no_payload_id};
        } else if (!std::holds_alternative<ValidChain>(verification)) {
            // ERROR
            const auto validation_error = std::get<ValidationError>(verification);
            log::Info() << "[PoSSync] fork_choice_update INVALID latest_valid_hash=" << validation_error.latest_valid_head
                        << " missing_block=" << validation_error.missing_block;
            co_return rpc::ForkChoiceUpdatedReply{{rpc::PayloadStatus::kInvalid, no_latest_valid_hash, "unknown execution error"}, no_payload_id};
        }

        // VALID
        // auto valid_chain = std::get<ValidChain>(verification);

        std::optional<Hash> finalized_block_hash =
            state.finalized_block_hash != kZeroHash ? std::optional<Hash>{state.finalized_block_hash} : std::nullopt;

        auto application = co_await exec_engine_.update_fork_choice(state.head_block_hash, finalized_block_hash);
        log::Info() << "[PoSSync] fork_choice_update " << (application.success ? "OK" : "KO")
                    << " current_head=" << application.current_head << " current_height=" << application.current_height;
        if (!application.success) {
            // at the moment application doesn't carry information to disambiguate between invalid head and
            // finalized_block_hash not found, so we need additional calls:

            if (finalized_block_hash) {
                auto is_canonical = co_await exec_engine_.is_canonical(*finalized_block_hash);
                if (!is_canonical) throw boost::system::system_error{rpc::to_system_code(rpc::ErrorCode::kInvalidForkChoiceState)};
            }
            if (state.safe_block_hash != kZeroHash) {
                auto is_canonical = co_await exec_engine_.is_canonical(state.safe_block_hash);
                if (!is_canonical) throw boost::system::system_error{rpc::to_system_code(rpc::ErrorCode::kInvalidForkChoiceState)};
            }

            co_return rpc::ForkChoiceUpdatedReply{{rpc::PayloadStatus::kInvalid, application.current_head, "invalid fork choice update"}, no_payload_id};
        }

        uint64_t buildProcessId = 0;
        if (attributes) {
            // payload build process
            if (attributes->timestamp <= head_header->timestamp) {
                throw boost::system::system_error{rpc::to_system_code(rpc::ErrorCode::kInvalidPayloadAttributes)};
                // in this case spec states that forkchoiceState update MUST NOT be rolled back
            }

            // buildProcessId = exec_engine_.build_payload(head_header_hash, attributes);
        }

        co_return rpc::ForkChoiceUpdatedReply{{rpc::PayloadStatus::kValid, state.head_block_hash}, buildProcessId};

    } catch (const boost::system::system_error& e) {
        log::Error() << "PoSSync: error processing fork-choice: " << e.what();
        throw;
    } catch (const std::exception& e) {
        log::Error() << "PoSSync: unexpected error processing fork-choice: " << e.what();
        throw;
    }
}

auto PoSSync::get_payload(uint64_t /*payloadId*/) -> asio::awaitable<rpc::ExecutionPayloadAndValue> {
    // Implementation of engine_getPayloadVx method
    ensure_invariant(false, "get_payload not implemented");
    co_return rpc::ExecutionPayloadAndValue{};
}

auto PoSSync::get_payload_bodies_by_hash(const std::vector<Hash>& block_hashes) -> asio::awaitable<rpc::ExecutionPayloadBodies> {
    rpc::ExecutionPayloadBodies payload_bodies;
    payload_bodies.resize(block_hashes.size());
    for (const auto& bh : block_hashes) {
        const auto block_body{co_await exec_engine_.get_body(bh)};
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

auto PoSSync::get_payload_bodies_by_range(BlockNum start, uint64_t count) -> asio::awaitable<rpc::ExecutionPayloadBodies> {
    rpc::ExecutionPayloadBodies payload_bodies;
    payload_bodies.resize(count);
    for (BlockNum number{start}; number < start + count; ++number) {
        const auto block_body{co_await exec_engine_.get_body(number)};
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