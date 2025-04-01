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

#include "direct_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/test_util/kv_test_base.hpp>
#include <silkworm/db/test_util/test_database_context.hpp>
#include <silkworm/infra/test_util/fixture.hpp>

namespace silkworm::db::kv::api {

using namespace silkworm::test_util;
using test_util::TestDataStore;

struct DirectServiceTest : public test_util::KVTestBase {
    Task<void> consumer(std::optional<StateChangeSet> change_set) {
        if (!change_set) co_return;
        change_set_vector.push_back(*change_set);
    }

    TemporaryDirectory tmp_dir;
    TestDataStore data_store{tmp_dir};
    ChainConfig chain_config{kMainnetConfig};

    StateChangeChannelPtr channel{std::make_shared<StateChangeChannel>(ioc_.get_executor())};
    concurrency::Channel<StateChangesCall> state_changes_calls_channel{ioc_.get_executor()};
    std::unique_ptr<StateCache> state_cache{std::make_unique<CoherentStateCache>()};
    DirectService service{ServiceRouter{state_changes_calls_channel}, data_store->ref(), chain_config, state_cache.get()};
    std::vector<StateChangeSet> change_set_vector;
};

TEST_CASE_METHOD(DirectServiceTest, "state_changes: state change sets", "[db][kv][api][direct_service]") {
    const std::vector<std::vector<StateChangeSet>> fixtures{
        {},
        {StateChangeSet{}},
        {StateChangeSet{}, StateChangeSet{}},
        {StateChangeSet{}, StateChangeSet{}, StateChangeSet{}},
    };
    StateChangeOptions options;
    auto state_changes_future = spawn(service.state_changes(options, [this](auto cs) -> Task<void> {
        co_await consumer(cs);
    }));
    for (const auto& expected_change_sets : fixtures) {
        SECTION("expected_change_sets size=" + std::to_string(expected_change_sets.size())) {
            spawn_and_wait([&]() -> Task<void> {
                auto state_changes_call = co_await state_changes_calls_channel.receive();
                state_changes_call.set_result(channel);
                for (const auto& change_set : expected_change_sets) {
                    co_await channel->send(change_set);
                }
            });
            spawn(channel->send({}));
            CHECK_NOTHROW(state_changes_future.get());
            CHECK(change_set_vector == expected_change_sets);
        }
    }
}

}  // namespace silkworm::db::kv::api
