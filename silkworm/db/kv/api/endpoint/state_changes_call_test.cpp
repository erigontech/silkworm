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

#include "state_changes_call.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/test_util/kv_test_base.hpp>

namespace silkworm::db::kv::api {

struct StateChangesCallTest : public test_util::KVTestBase {
    Task<std::optional<StateChangeSet>> client_receive_one(StateChangesCall& call) const {
        auto client_channel = co_await call.result();
        co_return co_await client_channel->receive();
    }

    Task<std::vector<StateChangeSet>> client_receive_all_until_closed(StateChangesCall& call) const {
        auto client_channel = co_await call.result();
        std::vector<StateChangeSet> change_set_sequence;
        while (true) {
            auto change_set = co_await client_channel->receive();
            if (!change_set) break;
            change_set_sequence.emplace_back(std::move(*change_set));
        }
        co_return change_set_sequence;
    }

    StateChangeChannelPtr channel{std::make_shared<StateChangeChannel>(ioc_.get_executor())};
};

TEST_CASE_METHOD(StateChangesCallTest, "one state change set", "[db][kv][api][state_changes_call]") {
    StateChangesCall call{StateChangeOptions{}, ioc_.get_executor()};
    call.set_result(channel);
    auto change_set_future = spawn(client_receive_one(call));
    const StateChangeSet empty_change_set{};
    spawn(channel->send(empty_change_set));
    CHECK(change_set_future.get() == empty_change_set);
}

TEST_CASE_METHOD(StateChangesCallTest, "many state change sets", "[db][kv][api][state_changes_call]") {
    StateChangesCall call{StateChangeOptions{}, ioc_.get_executor()};
    call.set_result(channel);
    auto change_set_vector_future = spawn(client_receive_all_until_closed(call));
    const std::vector<StateChangeSet> change_set_vector{StateChangeSet{}, StateChangeSet{}, StateChangeSet{}};
    for (const auto& change_set : change_set_vector) {
        spawn(channel->send(change_set));
    }
    spawn(channel->send({}));
    CHECK(change_set_vector_future.get() == change_set_vector);
}

}  // namespace silkworm::db::kv::api
