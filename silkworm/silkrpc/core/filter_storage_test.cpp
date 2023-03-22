/*
   Copyright 2023 The Silkrpc Authors

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

#include "filter_storage.hpp"

#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>
#include <thread>

#include "silkworm/silkrpc/json/types.hpp"

namespace silkrpc::filter {

using Catch::Matchers::Message;

TEST_CASE("FilterStorage base") {
    FilterStorage filter_storage{3, 1};
    SECTION("adding 1 entry") {
        StoredFilter filter;
        const auto filter_id = filter_storage.add_filter(filter);

        CHECK(filter_id.has_value() == true);
        CHECK(filter_storage.size() == 1);
    }
    SECTION("getting 1 entry") {
        auto json = R"({
            "address": "0x6090a6e47849629b7245dfa1ca21d94cd15878ef",
            "fromBlock": "0x3d0000",
            "toBlock": "0x3d2600"
        })"_json;

        const auto filter_id = filter_storage.add_filter(json);
        const auto filter = filter_storage.get_filter(filter_id.value());
        CHECK(filter.has_value() == true);

        const nlohmann::json result = filter.value();
        CHECK(result == json);
    }
    SECTION("removing 1 entry") {
        StoredFilter filter;
        const auto filter_id = filter_storage.add_filter(filter);
        auto result = filter_storage.remove_filter(filter_id.value());
        CHECK(result == true);
        CHECK(filter_storage.size() == 0);
    }
    SECTION("adding 2 entries") {
        StoredFilter filter;
        const auto filter_id_1 = filter_storage.add_filter(filter);
        const auto filter_id_2 = filter_storage.add_filter(filter);

        CHECK(filter_id_1.has_value() == true);
        CHECK(filter_id_2.has_value() == true);
        CHECK(filter_id_1.value() != filter_id_2.value());
        CHECK(filter_storage.size() == 2);
    }
    SECTION("adding 3 entries") {
        StoredFilter filter;
        filter_storage.add_filter(filter);
        filter_storage.add_filter(filter);
        const auto filter_id = filter_storage.add_filter(filter);

        CHECK(filter_id.has_value() == true);
        CHECK(filter_storage.size() == 3);
    }
    SECTION("adding too many entries") {
        StoredFilter filter;
        filter_storage.add_filter(filter);
        filter_storage.add_filter(filter);
        filter_storage.add_filter(filter);
        const auto filter_id = filter_storage.add_filter(filter);

        CHECK(filter_id.has_value() == false);
        CHECK(filter_storage.size() == 3);
    }
    SECTION("filter expires") {
        StoredFilter filter;
        const auto filter_id = filter_storage.add_filter(filter);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        const auto filter_opt = filter_storage.get_filter(filter_id.value());

        CHECK(filter_opt.has_value() == false);
        CHECK(filter_storage.size() == 0);
    }
    SECTION("filters expire") {
        StoredFilter filter;
        filter_storage.add_filter(filter);
        filter_storage.add_filter(filter);
        filter_storage.add_filter(filter);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        const auto filter_id = filter_storage.add_filter(filter);

        CHECK(filter_id.has_value() == true);
        CHECK(filter_storage.size() == 1);
    }
}

TEST_CASE("FilterStorage enhanced") {
    std::uint64_t count = 0;
    std::uint64_t max_keys = 3;
    Generator default_generator = [&]() {return count++ % max_keys;};

    FilterStorage filter_storage{default_generator, 2 * max_keys, 1};
    SECTION("keys OK") {
        StoredFilter filter;
        filter_storage.add_filter(filter);
        filter_storage.add_filter(filter);
        const auto filter_id = filter_storage.add_filter(filter);

        CHECK(filter_id.has_value() == true);
        CHECK(filter_storage.size() == 3);
    }
    SECTION("no more keys") {
        StoredFilter filter;
        filter_storage.add_filter(filter);
        filter_storage.add_filter(filter);
        filter_storage.add_filter(filter);
        const auto filter_id = filter_storage.add_filter(filter);

        CHECK(filter_id.has_value() == false);
        CHECK(filter_storage.size() == 3);
    }
}

} // namespace silkrpc::filter

