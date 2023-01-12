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

#include "sync_engine.hpp"

#include <silkworm/common/as_range.hpp>

namespace silkworm::chainsync {

SyncEngine::SyncEngine(BlockExchange& be, stagedsync::ExecutionEngine& ee)
    : block_exchange_{be},
      exec_engine_{ee},
      chain_fork_view_{ee.get_headers_head()} {

    block_exchange_.initial_state(exec_engine_.get_last_headers(65536));
}

auto SyncEngine::forward_and_insert_blocks() -> NewHeight {
    using ResultQueue = BlockExchange::ResultQueue;

    ResultQueue& downloading = block_exchange_.result_queue();

    auto current_header_head = exec_engine_.get_headers_head();
    block_exchange_.download_headers(current_header_head.number, BlockExchange::kTipOfTheChain);

    while (!is_stopping() && !block_exchange_.in_sync()) {
        std::variant<Headers, Blocks> result;
        bool present = downloading.timed_wait_and_pop(result, 100ms);
        if (!present) continue;

        if (std::holds_alternative<Headers>(result)) {
            auto& headers = std::get<Headers>(result);
            as_range::for_each(headers, [this](const auto& header) {
                chain_fork_view_.add(*header);
            });
            exec_engine_.insert_headers(headers);
            current_height_ = chain_fork_view_.head_height();

            block_exchange_.download_bodies(headers);

            send_new_header_announcements();
        }

        if (std::holds_alternative<Blocks>(result)) {
            auto& blocks = std::get<Blocks>(result);
            exec_engine_.insert_bodies(blocks);

            // compute new head
            auto highest_block = std::max_element(bodies.begin(), bodies.end(), [](shared_ptr<Block>& a, shared_ptr<Block>& b) {
                return a->header.number < b->header.number;
            });
            if (highest_block->get()->header.number > current_head.number) {
                current_head = {.number = highest_block->get()->header.number, .hash = highest_block->get()->header.hash()};
            }

            send_new_block_announcements();
        }
    };

    block_exchange_.stop_header_downloading();
    block_exchange_.stop_body_downloading();


    return {.new_head = current_head, .new_height = current_height_};
}

void SyncEngine::unwind(HeaderSync& headers_stage, BodySync& bodies_stage, UnwindPoint unwind_point) {
    bodies_stage.unwind(unwind_point);

    headers_stage.unwind(unwind_point);
}

void SyncEngine::execution_loop() {
    using namespace stagedsync;
    using ValidChain = ExecutionEngine::ValidChain;
    using ValidationError = ExecutionEngine::ValidationError;
    using InvalidChain = ExecutionEngine::InvalidChain;

    while (!is_stopping()) {

        NewHeight new_height = forward_and_insert_blocks();

        auto verification = exec_engine_.verify_chain(new_height.hash);

        if (std::holds_alternative<InvalidChain>(verification)) {
            auto invalid_chain = std::get<InvalidChain>(verification);

            unwind(headers_stage, bodies_stage, {invalid_chain.unwind_point});

            if (!invalid_chain.bad_headers.empty()) {
                update_bad_headers(std::move(invalid_chain.bad_headers));
            }

            exec_engine_.notify_fork_choice_updated(invalid_chain.unwind_head);

            continue;
        } else if (std::holds_alternative<ValidationError>(verification)) {
            throw std::logic_error("Consensus, validation error");
        }

        auto valid_chain = std::get<ValidChain>(verification);

        if (valid_chain.current_point != new_height.block_num) {
            // ???
        }

        exec_engine_.notify_fork_choice_updated(new_height.hash);
    }
};

auto SyncEngine::update_bad_headers(std::set<Hash> bad_headers) -> std::shared_ptr<InternalMessage<void>> {
    auto message = std::make_shared<InternalMessage<void>>(
        [bads = std::move(bad_headers)](HeaderChain& wc, BodySequence&) { wc.add_bad_headers(bads); });

    block_exchange_.accept(message);

    return message;
}

}  // namespace silkworm::chainsync