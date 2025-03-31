// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "remote_client.hpp"

#include <gmock/gmock.h>

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/infra/grpc/test_util/interfaces/kv_mock_fix24351.grpc.pb.h>
#include <silkworm/infra/grpc/test_util/test_runner.hpp>

#include "../test_util/sample_protos.hpp"

namespace silkworm::db::kv::grpc::client {

using namespace silkworm::grpc::test_util;
using namespace silkworm::db::kv::test_util;
namespace proto = ::remote;

using StrictMockKVStub = testing::StrictMock<proto::FixIssue24351_MockKVStub>;

struct RemoteClientTestRunner : public TestRunner<RemoteClient, StrictMockKVStub> {
    std::unique_ptr<api::StateCache> state_cache{std::make_unique<api::CoherentStateCache>()};
    // We're not testing blocks here, so we don't care about proper block provider
    chain::BlockProvider block_provider{
        [](BlockNum, HashAsSpan, bool, Block&) -> Task<bool> { co_return false; }};
    // We're not testing blocks here, so we don't care about proper block-number-from-txn-hash provider
    chain::BlockNumFromTxnHashProvider block_num_from_txn_hash_provider{
        [](HashAsSpan) -> Task<std::optional<std::pair<BlockNum, TxnId>>> { co_return std::make_pair(0, 0); }};
    chain::BlockNumFromBlockHashProvider block_num_from_block_hash_provider{
        [](HashAsSpan) -> Task<std::optional<BlockNum>> { co_return std::nullopt; }};
    chain::CanonicalBlockHashFromNumberProvider canonical_block_hash_from_number_provider{
        [](BlockNum) -> Task<std::optional<evmc::bytes32>> { co_return 0; }};

  protected:
    RemoteClient make_api_client() override {
        return RemoteClient{std::move(stub_),
                            grpc_context_,
                            state_cache.get(),
                            {block_provider,
                             block_num_from_txn_hash_provider,
                             block_num_from_block_hash_provider,
                             canonical_block_hash_from_number_provider}};
    }
};

}  // namespace silkworm::db::kv::grpc::client
