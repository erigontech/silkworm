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

namespace silkworm::stagedsync::recovery {

RecoveryWorker::RecoveryWorker(uint32_t id, size_t data_size) : id_(id), data_size_{data_size} {
    // Try allocate enough memory to store results output
    assert(data_size % kAddressLength == 0);
    data_ = static_cast<uint8_t*>(std::calloc(1, data_size_));
    if (!data_) {
        throw std::runtime_error("Memory allocation failed");
    }
    context_ = ecdsa::create_context();
    if (!context_) {
        throw std::runtime_error("Could not create elliptic curve context");
    }
}

void RecoveryWorker::set_work(uint32_t batch_id, std::vector<package>& farm_batch) {
    batch_id_ = batch_id;
    batch_.swap(farm_batch);
    status_.store(Status::Working);
    Worker::kick();
}

std::string RecoveryWorker::get_error() const {
    return (status_.load() == Status::Error) ? last_error_ : std::string();
}

RecoveryWorker::Status RecoveryWorker::get_status() const { return status_.load(); }

bool RecoveryWorker::pull_results(std::vector<std::pair<BlockNum, ByteView>>& out_results) {
    Status expected_status{Status::ResultsReady};
    if (status_.compare_exchange_strong(expected_status, Status::Idle)) {
        std::swap(out_results, results_);
        return true;
    }
    return false;
}

void RecoveryWorker::work() {
    while (wait_for_kick()) {
        /**
         * Each work package is a pair of BlockNum + Transaction data.
         * Work packages are processed in order and recovered sender's addresses are
         * stored in allocated memory area. At block level break s byteview of
         * memory area for addresses of the block is created and stored in results_ vector
         */

        results_.clear();
        BlockNum block_num{batch_.front().block_num};
        size_t block_data_offset{0};
        size_t block_data_length{0};

        for (auto const& package : batch_) {
            // On block switching store the results
            if (block_num != package.block_num) {
                if (should_stop()) {
                    status_.store(Status::Aborted);
                    break;
                }

                ByteView data_view{&data_[block_data_offset], block_data_length};
                results_.emplace_back(block_num, data_view);

                block_data_offset += block_data_length;
                block_data_length = 0;
                block_num = package.block_num;
            }

            std::optional<evmc::address> recovered_address{ecdsa::recover_address(
                context_, full_view(package.hash.bytes), full_view(package.signature), package.odd_y_parity)};

            if (recovered_address.has_value()) {
                std::memcpy(&data_[block_data_offset + block_data_length], recovered_address->bytes, kAddressLength);
                block_data_length += kAddressLength;
            } else {
                last_error_ = "Public key recovery failed at block #" + std::to_string(package.block_num);
                status_.store(Status::Error);
                break;  // No need to process other transactions
            }
        }

        if (status_.load() == Status::Working) {
            // Store results for last block
            if (block_data_length) {
                ByteView data_view{&data_[block_data_offset], block_data_length};
                results_.emplace_back(block_num, data_view);
            }
            status_.store(Status::ResultsReady);
        }

        // Raise finished event
        signal_completed(this);
        batch_.resize(0);
    }

    std::free(data_);
    std::free(context_);
    batch_.clear();
}

}  // namespace silkworm::stagedsync::recovery
