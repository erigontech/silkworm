/*
   Copyright 2024 The Silkworm Authors

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

#include "remote_chain_storage.hpp"

#include <string>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>

namespace silkworm::db::chain {

using Catch::Matchers::Message;
using testing::_;
using testing::InvokeWithoutArgs;
using testing::Unused;

static Bytes kBlockHash{*from_hex("439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff")};
static Bytes kInvalidJsonChainConfig{*from_hex("000102")};
static Bytes kChainConfig{*from_hex(
    "7b226265726c696e426c6f636b223a31323234343030302c2262797a6"
    "16e7469756d426c6f636b223a343337303030302c22636861696e4964223a312c22636f6e7374616e74696e6f706c65426c6f636b223a"
    "373238303030302c2264616f466f726b426c6f636b223a313932303030302c22656970313530426c6f636b223a323436333030302c226"
    "56970313535426c6f636b223a323637353030302c22657468617368223a7b7d2c22686f6d657374656164426c6f636b223a3131353030"
    "30302c22697374616e62756c426c6f636b223a393036393030302c226c6f6e646f6e426c6f636b223a31323936353030302c226d75697"
    "2476c6163696572426c6f636b223a393230303030302c2270657465727362757267426c6f636b223a373238303030307d")};

struct RemoteChainStorageTest : public silkworm::test_util::ContextTestBase {
    test_util::MockTransaction transaction;
    RemoteChainStorage storage{transaction, Providers{}};
};

TEST_CASE_METHOD(RemoteChainStorageTest, "read_chain_config") {
    SECTION("empty chain data") {
        EXPECT_CALL(transaction, get_one(table::kCanonicalHashesName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kBlockHash;
        }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return Bytes{};
        }));
#ifdef SILKWORM_SANITIZE  // Avoid comparison against exception message: it triggers a TSAN data race seemingly related to libstdc++ string implementation
        CHECK_THROWS_AS(spawn_and_wait(storage.read_chain_config()), std::invalid_argument);
#else
        CHECK_THROWS_MATCHES(spawn_and_wait(storage.read_chain_config()), std::invalid_argument, Message("empty chain config data in read_chain_config"));
#endif  // SILKWORM_SANITIZE
    }

    SECTION("invalid JSON chain data") {
        EXPECT_CALL(transaction, get_one(table::kCanonicalHashesName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kBlockHash;
        }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kInvalidJsonChainConfig;
        }));
        CHECK_THROWS_AS(spawn_and_wait(storage.read_chain_config()), nlohmann::json::parse_error);
    }

    SECTION("valid JSON chain data") {
        EXPECT_CALL(transaction, get_one(table::kCanonicalHashesName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kBlockHash;
        }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kChainConfig;
        }));
        const auto chain_config = spawn_and_wait(storage.read_chain_config());
        CHECK(chain_config.genesis_hash == 0x439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff_bytes32);
        CHECK(chain_config.to_json() == R"({
                "berlinBlock":12244000,
                "byzantiumBlock":4370000,
                "chainId":1,
                "constantinopleBlock":7280000,
                "daoForkBlock":1920000,
                "eip150Block":2463000,
                "eip155Block":2675000,
                "ethash":{},
                "genesisBlockHash":"0x439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff",
                "homesteadBlock":1150000,
                "istanbulBlock":9069000,
                "londonBlock":12965000,
                "muirGlacierBlock":9200000,
                "petersburgBlock":7280000
            })"_json);
    }
}

}  // namespace silkworm::db::chain
