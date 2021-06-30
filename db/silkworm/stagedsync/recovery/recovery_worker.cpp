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
    // Try allocate enough memory to store
    // results output
    data_ = static_cast<uint8_t*>(std::calloc(1, data_size_));
    if (!data_) {
        throw std::runtime_error("Memory allocation failed");
    }
};


void RecoveryWorker::set_work(uint32_t batch_id, std::unique_ptr<std::vector<package>> batch) {
    batch_ = std::move(batch);
    batch_id_ = batch_id;
    status_.store(Status::Working);
    Worker::kick();
}

uint32_t RecoveryWorker::get_id() const { return id_; };
uint32_t RecoveryWorker::get_batch_id() const { return batch_id_; };
std::string RecoveryWorker::get_error(void) const { return last_error_; };
RecoveryWorker::Status RecoveryWorker::get_status(void) const { return status_.load(); };

bool RecoveryWorker::pull_results(Status status, std::vector<std::pair<uint64_t, iovec>>& out) {
    if (status_.compare_exchange_strong(status, Status::Idle)) {
        std::swap(out, results_);
        return true;
    };
    return false;
};

void RecoveryWorker::work() {
    while (wait_for_kick()) {
        // Prefer swapping with a new vector instead of clear
        std::vector<std::pair<uint64_t, iovec>>().swap(results_);

        uint64_t block_num{(*batch_).front().block_num};
        size_t block_result_offset{0};
        size_t block_result_length{0};

        for (auto const& package : (*batch_)) {
            // On block switching store the results
            if (block_num != package.block_num) {
                iovec result{&data_[block_result_offset], block_result_length};
                results_.push_back({block_num, result});
                block_result_offset += block_result_length;
                block_result_length = 0;
                block_num = package.block_num;
                if (should_stop()) {
                    status_.store(Status::Aborted);
                    break;
                }
            }

            std::optional<Bytes> recovered{
                ecdsa::recover(full_view(package.hash.bytes), full_view(package.signature), package.odd_y_parity)};

            if (recovered.has_value() && recovered->at(0) == 4u) {
                auto keyHash{ethash::keccak256(recovered->data() + 1, recovered->length() - 1)};
                std::memcpy(&data_[block_result_offset + block_result_length],
                            &keyHash.bytes[sizeof(keyHash) - kAddressLength], kAddressLength);
                block_result_length += kAddressLength;
            } else {
                last_error_ = "Public key recovery failed at block #" + std::to_string(package.block_num);
                status_.store(Status::Error);
                break;  // No need to process other txns
            }
        }

        if (status_.load() == Status::Working) {
            // Store results for last block
            if (block_result_length) {
                iovec result{&data_[block_result_offset], block_result_length};
                results_.push_back({block_num, result});
            }
            status_.store(Status::ResultsReady);
        }

        // Raise finished event
        signal_completed(this, batch_id_);
        batch_.reset();
    }

    std::free(data_);
};
};
