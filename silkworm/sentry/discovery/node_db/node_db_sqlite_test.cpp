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
#include <future>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::sentry::discovery::node_db {

using namespace boost::asio;

template <typename TResult>
static void poll_context_until_future_is_ready(io_context& context, std::future<TResult>& future) {
    using namespace std::chrono_literals;
    context.restart();
    while (future.wait_for(0s) != std::future_status::ready) {
        context.poll_one();
    }
}

template <typename TResult>
static TResult run(io_context& context, Task<TResult> task) {
    auto future = co_spawn(context, std::move(task), use_future);
    poll_context_until_future_is_ready(context, future);
    return future.get();
}

bool operator==(const NodeAddress& lhs, const NodeAddress& rhs) {
    return (lhs.ip == rhs.ip) &&
           (lhs.port_disc == rhs.port_disc) &&
           (lhs.port_rlpx == rhs.port_rlpx);
}

TEST_CASE("NodeDbSqlite") {
    io_context context;

    NodeDbSqlite db_sqlite;
    db_sqlite.setup_in_memory();
    NodeDb& db = db_sqlite.interface();

    NodeId test_id{from_hex("ba85011c70bcc5c04d8607d3a0ed29aa6179c092cbdda10d5d32684fb33ed01bd94f588ca8f91ac48318087dcb02eaf36773a7a453f0eedd6742af668097b29c").value()};
    NodeAddress test_address{
        ip::make_address("10.0.1.16"),
        30304,
        30303,
    };

    SECTION("insert_and_find_address.v4") {
        run(context, db.upsert_node_address(test_id, test_address));
        auto address = run(context, db.find_node_address_v4(test_id));
        REQUIRE(address.has_value());
        CHECK(*address == test_address);
        auto address_v6 = run(context, db.find_node_address_v6(test_id));
        CHECK_FALSE(address_v6.has_value());
    }

    SECTION("insert_and_find_address.v6") {
        test_address.ip = ip::make_address("::ffff:a00:110");
        run(context, db.upsert_node_address(test_id, test_address));
        auto address = run(context, db.find_node_address_v6(test_id));
        REQUIRE(address.has_value());
        CHECK(*address == test_address);
        auto address_v4 = run(context, db.find_node_address_v4(test_id));
        CHECK_FALSE(address_v4.has_value());
    }

    SECTION("update_address") {
        run(context, db.upsert_node_address(test_id, test_address));
        NodeAddress test_address2{
            ip::make_address("10.0.1.17"),
            30306,
            30305,
        };
        run(context, db.upsert_node_address(test_id, test_address2));
        auto address = run(context, db.find_node_address_v4(test_id));
        REQUIRE(address.has_value());
        CHECK(*address == test_address2);
    }

    SECTION("insert_address_with_zero_ports") {
        test_address.port_disc = 0;
        test_address.port_rlpx = 0;
        run(context, db.upsert_node_address(test_id, test_address));
        auto address = run(context, db.find_node_address_v4(test_id));
        REQUIRE(address.has_value());
        CHECK(*address == test_address);
    }

    SECTION("insert_and_delete_node") {
        run(context, db.upsert_node_address(test_id, test_address));
        run(context, db.delete_node(test_id));
        auto address = run(context, db.find_node_address_v4(test_id));
        CHECK_FALSE(address.has_value());
    }

    SECTION("update_last_pong_time") {
        run(context, db.upsert_node_address(test_id, test_address));
        run(context, db.update_last_pong_time(test_id, std::chrono::system_clock::system_clock::now()));
    }
}

}  // namespace silkworm::sentry::discovery::node_db
