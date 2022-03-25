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

#include "cpp20_backport.hpp"

extern const uint64_t* preverified_hashes_mainnet_data();
extern size_t sizeof_preverified_hashes_mainnet_data();
extern uint64_t preverified_hashes_mainnet_height();

namespace silkworm {

void load_preverified_hashes(PreverifiedHashes& destination, const uint64_t* (*preverified_hashes_data)(),
                             size_t (*sizeof_preverified_hashes_data)(), uint64_t (*preverified_hashes_height)()) {
    auto data_size = sizeof_preverified_hashes_data();
    if (data_size == 0) return;

    auto data_ptr = reinterpret_cast<const evmc::bytes32*>(preverified_hashes_data());
    auto num_elements{data_size / sizeof(evmc::bytes32)};

    for (uint64_t i = 0; i < num_elements; ++i) {
        destination.hashes.insert(data_ptr[i]);
    }

    destination.height = preverified_hashes_height();
}

PreverifiedHashes PreverifiedHashes::load(uint64_t chain_id) {
    PreverifiedHashes result{};

    if (chain_id == 1) {
        load_preverified_hashes(result,
                                preverified_hashes_mainnet_data,
                                sizeof_preverified_hashes_mainnet_data,
                                preverified_hashes_mainnet_height);
    }

    return result;
}

}  // namespace silkworm