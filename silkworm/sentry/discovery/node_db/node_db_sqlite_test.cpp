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

#include "node_db_sqlite.hpp"

#include <chrono>

#include <catch2/catch.hpp>

#include <silkworm/infra/test_util/task_runner.hpp>

namespace silkworm::sentry::discovery::node_db {

using namespace boost::asio;

bool operator==(const NodeAddress& lhs, const NodeAddress& rhs) {
    return (lhs.ip == rhs.ip) &&
           (lhs.port_disc == rhs.port_disc) &&
           (lhs.port_rlpx == rhs.port_rlpx);
}

TEST_CASE("NodeDbSqlite") {
    test_util::TaskRunner runner;

    NodeDbSqlite db_sqlite{any_io_executor{runner.context().get_executor()}};
    db_sqlite.setup_in_memory();
    NodeDb& db = db_sqlite.interface();

    NodeId test_id = NodeId::deserialize_hex("ba85011c70bcc5c04d8607d3a0ed29aa6179c092cbdda10d5d32684fb33ed01bd94f588ca8f91ac48318087dcb02eaf36773a7a453f0eedd6742af668097b29c");
    NodeAddress test_address{
        ip::make_address("10.0.1.16"),
        30304,
        30303,
    };

    SECTION("insert_and_find_address.v4") {
        runner.run(db.upsert_node_address(test_id, test_address));
        auto address = runner.run(db.find_node_address_v4(test_id));
        REQUIRE(address.has_value());
        CHECK(*address == test_address);
        auto address_v6 = runner.run(db.find_node_address_v6(test_id));
        CHECK_FALSE(address_v6.has_value());
    }

    SECTION("insert_and_find_address.v6") {
        test_address.ip = ip::make_address("::ffff:a00:110");
        runner.run(db.upsert_node_address(test_id, test_address));
        auto address = runner.run(db.find_node_address_v6(test_id));
        REQUIRE(address.has_value());
        CHECK(*address == test_address);
        auto address_v4 = runner.run(db.find_node_address_v4(test_id));
        CHECK_FALSE(address_v4.has_value());
    }

    SECTION("update_address") {
        runner.run(db.upsert_node_address(test_id, test_address));
        NodeAddress test_address2{
            ip::make_address("10.0.1.17"),
            30306,
            30305,
        };
        runner.run(db.upsert_node_address(test_id, test_address2));
        auto address = runner.run(db.find_node_address_v4(test_id));
        REQUIRE(address.has_value());
        CHECK(*address == test_address2);
    }

    SECTION("insert_address_with_zero_ports") {
        test_address.port_disc = 0;
        test_address.port_rlpx = 0;
        runner.run(db.upsert_node_address(test_id, test_address));
        auto address = runner.run(db.find_node_address_v4(test_id));
        REQUIRE(address.has_value());
        CHECK(*address == test_address);
    }

    SECTION("insert_and_delete_node") {
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.delete_node(test_id));
        auto address = runner.run(db.find_node_address_v4(test_id));
        CHECK_FALSE(address.has_value());
    }

    SECTION("update_and_find_last_ping_time") {
        runner.run(db.upsert_node_address(test_id, test_address));
        auto expected_value = std::chrono::system_clock::system_clock::now();
        runner.run(db.update_last_ping_time(test_id, expected_value));
        auto actual_value = runner.run(db.find_last_ping_time(test_id));
        REQUIRE(actual_value.has_value());
        CHECK(std::chrono::duration_cast<std::chrono::seconds>(*actual_value - expected_value).count() == 0);
    }

    SECTION("update_and_find_last_pong_time") {
        runner.run(db.upsert_node_address(test_id, test_address));
        auto expected_value = std::chrono::system_clock::system_clock::now();
        runner.run(db.update_last_pong_time(test_id, expected_value));
        auto actual_value = runner.run(db.find_last_pong_time(test_id));
        REQUIRE(actual_value.has_value());
        CHECK(std::chrono::duration_cast<std::chrono::seconds>(*actual_value - expected_value).count() == 0);
    }
}

}  // namespace silkworm::sentry::discovery::node_db
