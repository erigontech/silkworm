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

#include "status_data.hpp"

#include <silkworm/chain/config.hpp>

namespace silkworm::sentry::eth {

StatusData StatusData::test_instance() {
    Bytes genesis_hash{*kMainnetConfig.genesis_hash};
    auto fork_block_numbers = kMainnetConfig.distinct_fork_numbers();
    const BlockNum head_block_num = 0;

    auto message = StatusMessage{
        67,  // protocol version
        kMainnetConfig.chain_id,
        17179869184,  // total difficulty
        genesis_hash,
        genesis_hash,
        ForkId{
            genesis_hash,
            fork_block_numbers,
            head_block_num,
        },
    };

    return StatusData{
        std::move(fork_block_numbers),
        head_block_num,
        std::move(message),
    };
}

}  // namespace silkworm::sentry::eth
