// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "filter_storage.hpp"

#include <thread>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

TEST_CASE("FilterStorage base") {
    FilterStorage filter_storage{3, 0.01};
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
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto filter_opt = filter_storage.get_filter(filter_id.value());

        CHECK(filter_opt.has_value() == false);
        CHECK(filter_storage.size() == 0);
    }
    SECTION("filters expire") {
        StoredFilter filter;
        filter_storage.add_filter(filter);
        filter_storage.add_filter(filter);
        filter_storage.add_filter(filter);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto filter_id = filter_storage.add_filter(filter);

        CHECK(filter_id.has_value() == true);
        CHECK(filter_storage.size() == 1);
    }
}

TEST_CASE("FilterStorage enhanced") {
    std::uint64_t count = 0;
    std::uint64_t max_keys = 3;
    Generator default_generator = [&]() { return count++ % max_keys; };

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

}  // namespace silkworm::rpc
