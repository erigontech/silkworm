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

#ifndef SILKWORM_STATE_MEMORY_BUFFER_H_
#define SILKWORM_STATE_MEMORY_BUFFER_H_

#include <silkworm/state/buffer.hpp>
#include <unordered_map>

namespace silkworm {

/// MemoryBuffer holds all state in memory.
class MemoryBuffer : public StateBuffer {
  public:
    std::optional<Account> read_account(const evmc::address& address) const noexcept override;

    Bytes read_code(const evmc::bytes32& code_hash) const noexcept override;

    evmc::bytes32 read_storage(const evmc::address& address, uint64_t incarnation,
                               const evmc::bytes32& location) const noexcept override;

    uint64_t previous_incarnation(const evmc::address& address) const noexcept override;

    std::optional<BlockHeader> read_header(uint64_t block_number,
                                           const evmc::bytes32& block_hash) const noexcept override;

    void insert_header(const BlockHeader& block_header) override;

    void insert_receipts(uint64_t block_number, const std::vector<Receipt>& receipts) override;

    void begin_block(uint64_t block_number) override;

    void update_account(const evmc::address& address, std::optional<Account> initial,
                        std::optional<Account> current) override;

    void update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                             ByteView code) override;

    void update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location,
                        const evmc::bytes32& initial, const evmc::bytes32& current) override;

  private:
    std::unordered_map<evmc::address, Account> accounts_;

    // hash -> code
    std::unordered_map<evmc::bytes32, Bytes> code_;

    std::unordered_map<evmc::address, uint64_t> prev_incarnations_;

    // address -> incarnation -> location -> value
    std::unordered_map<evmc::address, std::unordered_map<uint64_t, std::unordered_map<evmc::bytes32, evmc::bytes32>>>
        storage_;

    // block number -> hash -> header
    std::unordered_map<uint64_t, std::unordered_map<evmc::bytes32, BlockHeader>> headers_;
};

}  // namespace silkworm

#endif  // SILKWORM_STATE_MEMORY_BUFFER_H_
