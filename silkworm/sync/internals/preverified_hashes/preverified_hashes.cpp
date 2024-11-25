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

#include "preverified_hashes.hpp"

#include <mutex>

#include <silkworm/infra/common/environment.hpp>

extern const uint64_t* preverified_hashes_mainnet_data();
extern size_t sizeof_preverified_hashes_mainnet_data();
extern uint64_t preverified_hashes_mainnet_block_num();

namespace silkworm {

void load_preverified_hashes(PreverifiedHashes& destination, const uint64_t* (*preverified_hashes_data)(),
                             size_t (*sizeof_preverified_hashes_data)(), uint64_t (*preverified_hashes_block_num)()) {
    auto data_size = sizeof_preverified_hashes_data();
    if (data_size == 0) return;

    auto data_ptr = reinterpret_cast<const evmc::bytes32*>(preverified_hashes_data());
    auto num_elements{data_size / sizeof(evmc::bytes32)};
    if (num_elements < 2) return;

    for (uint64_t i = 0; i < num_elements; ++i) {
        destination.hashes.insert(data_ptr[i]);
    }

    destination.block_num = preverified_hashes_block_num();
    destination.step = preverified_hashes_block_num() / (num_elements - 1);
}

PreverifiedHashes& PreverifiedHashes::load(uint64_t chain_id) {
    static PreverifiedHashes kEmpty;
    static PreverifiedHashes mainnet_instance;
    static std::once_flag load_once_flag;

    if (Environment::are_pre_verified_hashes_disabled()) {
        return kEmpty;
    }

    if (chain_id == 1) {
        std::call_once(
            load_once_flag,
            load_preverified_hashes,
            mainnet_instance,
            preverified_hashes_mainnet_data,
            sizeof_preverified_hashes_mainnet_data,
            preverified_hashes_mainnet_block_num);
        return mainnet_instance;
    }

    return kEmpty;
}

bool PreverifiedHashes::contains(const evmc::bytes32& hash) const {
    return hashes.find(hash) != hashes.end();
}

}  // namespace silkworm
