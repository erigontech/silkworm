/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "recovery_worker.hpp"

#include <silkworm/common/log.hpp>
#include <silkworm/common/stopwatch.hpp>

namespace silkworm::stagedsync::recovery {

RecoveryWorker::~RecoveryWorker() {
    if (context_) {
        std::free(context_);
    }
    stop(true);
}

void RecoveryWorker::set_work(std::vector<RecoveryPackage>& farm_batch, bool kick) {
    batch_.swap(farm_batch);
    if (kick) {
        Worker::kick();
    }
}

void RecoveryWorker::work() {
    StopWatch sw;
    context_ = ecdsa::create_context();
    if (!context_) {
        throw std::runtime_error("Could not create elliptic curve context");
    }

    while (wait_for_kick()) {
        /**
         * Each work package is a pair of BlockNum + Transaction data.
         * Work packages are processed in order and recovered sender's addresses are
         * stored in allocated memory area. At block level break s byteview of
         * memory area for addresses of the block is created and stored in results_ vector
         */

        sw.start(true);
        BlockNum block_num{batch_.front().block_num};

        for (auto& package : batch_) {
            // On block switching check stopping
            if (block_num != package.block_num && is_stopping()) {
                throw std::runtime_error("Operation cancelled");
            }

            std::optional<evmc::address> recovered_address{
                ecdsa::recover_address(package.tx_hash.bytes, package.tx_signature, package.odd_y_parity, context_)};

            if (recovered_address.has_value()) {
                memcpy(package.tx_from.bytes, recovered_address.value().bytes, sizeof(evmc::address));
            } else {
                throw std::runtime_error("Unable to recover from address in block " + std::to_string(block_num));
            }
        }

        // Raise task completed event
        auto [_, elapsed]{sw.stop()};
        log::Trace(name_, {"task completed", StopWatch::format(elapsed)});
        signal_task_completed(this);
    }
}
}  // namespace silkworm::stagedsync::recovery
