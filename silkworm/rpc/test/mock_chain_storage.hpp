/*
   Copyright 2023 The Silkworm Authors

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

#pragma once

#include <memory>
#include <string>

#include <catch2/catch.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/storage/chain_storage.hpp>

namespace silkworm::rpc::test {

class MockChainStorage : public silkworm::rpc::ChainStorage {
  public:
    MOCK_METHOD((Task<std::optional<silkworm::ChainConfig>>), read_chain_config, (), (const override));

    MOCK_METHOD((Task<std::optional<ChainId>>), read_chain_id, (), (const override));

    MOCK_METHOD((Task<BlockNum>), highest_block_number, (), (const override));

    MOCK_METHOD((Task<std::optional<BlockNum>>), read_block_number, (const Hash&), (const override));

    MOCK_METHOD((Task<bool>), read_block, (HashAsSpan, BlockNum, bool, silkworm::Block&), (const override));
    MOCK_METHOD((Task<bool>), read_block, (const Hash&, BlockNum, silkworm::Block&), (const override));
    MOCK_METHOD((Task<bool>), read_block, (const Hash&, silkworm::Block&), (const override));
    MOCK_METHOD((Task<bool>), read_block, (BlockNum, bool, silkworm::Block&), (const override));

    MOCK_METHOD((Task<std::optional<BlockHeader>>), read_header, (BlockNum number, HashAsArray hash), (const override));
    MOCK_METHOD((Task<std::optional<BlockHeader>>), read_header, (BlockNum number, const Hash& hash), (const override));
    MOCK_METHOD((Task<std::optional<BlockHeader>>), read_header, (const Hash& hash), (const override));

    MOCK_METHOD((Task<std::vector<BlockHeader>>), read_sibling_headers, (BlockNum), (const override));

    MOCK_METHOD((Task<bool>), read_body, (BlockNum, HashAsArray, bool, silkworm::BlockBody&), (const override));
    MOCK_METHOD((Task<bool>), read_body, (const Hash&, BlockNum, silkworm::BlockBody&), (const override));
    MOCK_METHOD((Task<bool>), read_body, (const Hash&, silkworm::BlockBody&), (const override));

    MOCK_METHOD((Task<std::optional<Hash>>), read_canonical_hash, (BlockNum), (const override));

    MOCK_METHOD((Task<std::optional<BlockHeader>>), read_canonical_header, (BlockNum), (const override));

    MOCK_METHOD((Task<bool>), read_canonical_body, (BlockNum, BlockBody&), (const override));

    MOCK_METHOD((Task<bool>), read_canonical_block, (BlockNum, silkworm::Block&), (const override));

    MOCK_METHOD((Task<bool>), has_body, (BlockNum, HashAsArray), (const override));

    MOCK_METHOD((Task<bool>), has_body, (BlockNum, const Hash&), (const override));

    MOCK_METHOD((Task<bool>), read_rlp_transactions, (BlockNum, const evmc::bytes32&, std::vector<Bytes>&), (const override));

    MOCK_METHOD((Task<bool>), read_rlp_transaction, (const evmc::bytes32&, Bytes&), (const override));

    MOCK_METHOD((Task<std::optional<intx::uint256>>), read_total_difficulty, (const Hash& block_hash, BlockNum block_number), (const override));

    MOCK_METHOD((Task<std::optional<BlockNum>>), read_block_number_by_transaction_hash, (const evmc::bytes32& transaction_hash), (const override));
};

}  // namespace silkworm::rpc::test
