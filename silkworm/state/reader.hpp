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

#ifndef SILKWORM_STATE_READER_H_
#define SILKWORM_STATE_READER_H_

#include <optional>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm::state {

class HeaderReader {
   public:
    virtual std::optional<BlockHeader> read_header(uint64_t block_number,
                                                   const evmc::bytes32& block_hash) const noexcept = 0;
};

class Reader : public HeaderReader {
   public:
    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;

    explicit Reader(lmdb::Transaction& txn, std::optional<uint64_t> block_number = {}) noexcept
        : txn_{txn}, block_number_{block_number} {}

    std::optional<BlockHeader> read_header(uint64_t block_number,
                                           const evmc::bytes32& block_hash) const noexcept override;

    std::optional<Account> read_account(const evmc::address& address) const noexcept;

    Bytes read_code(const evmc::bytes32& code_hash) const noexcept;

    evmc::bytes32 read_storage(const evmc::address& address, uint64_t incarnation,
                               const evmc::bytes32& key) const noexcept;

    // Previous non-zero incarnation of an account; 0 if none exists
    uint64_t previous_incarnation(const evmc::address& address) const noexcept;

   private:
    lmdb::Transaction& txn_;
    std::optional<uint64_t> block_number_{};
};

}  // namespace silkworm::state

#endif  // SILKWORM_STATE_READER_H_
