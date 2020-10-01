/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_STATE_TEST_HEADER_DB_H_
#define SILKWORM_STATE_TEST_HEADER_DB_H_

#include <map>
#include <silkworm/state/reader.hpp>

namespace silkworm {

// Basic in-memory headers DB for testing
class TestHeaderDB : public state::HeaderReader {
   public:
    std::optional<BlockHeader> read_header(uint64_t block_number,
                                           const evmc::bytes32& block_hash) const noexcept override;

    void write_header(BlockHeader block_header);

   private:
    std::map<evmc::bytes32, BlockHeader> headers_{};
};

}  // namespace silkworm

#endif  // SILKWORM_STATE_TEST_HEADER_DB_H_
