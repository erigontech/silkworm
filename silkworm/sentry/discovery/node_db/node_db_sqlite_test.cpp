// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "node_db_sqlite.hpp"

#include <chrono>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/task_runner.hpp>

namespace silkworm::sentry::discovery::node_db {

namespace ip = boost::asio::ip;
using namespace std::chrono_literals;
using boost::asio::any_io_executor;

bool operator==(const NodeAddress& lhs, const NodeAddress& rhs) {
    return (lhs.ip == rhs.ip) &&
           (lhs.port_disc == rhs.port_disc) &&
           (lhs.port_rlpx == rhs.port_rlpx);
}

TEST_CASE("NodeDbSqlite") {
    test_util::TaskRunner runner;

    NodeDbSqlite db_sqlite{any_io_executor{runner.ioc().get_executor()}};
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
        bool is_inserted = runner.run(db.upsert_node_address(test_id, test_address));
        CHECK(is_inserted);
        NodeAddress test_address2{
            ip::make_address("10.0.1.17"),
            30306,
            30305,
        };
        is_inserted = runner.run(db.upsert_node_address(test_id, test_address2));
        CHECK_FALSE(is_inserted);
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

    SECTION("update_and_find_next_ping_time") {
        runner.run(db.upsert_node_address(test_id, test_address));
        auto expected_value = std::chrono::system_clock::system_clock::now();
        runner.run(db.update_next_ping_time(test_id, expected_value));
        auto actual_value = runner.run(db.find_next_ping_time(test_id));
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

    SECTION("update_and_find_ping_fails") {
        runner.run(db.upsert_node_address(test_id, test_address));
        size_t expected_value = 5;
        runner.run(db.update_ping_fails(test_id, expected_value));
        auto actual_value = runner.run(db.find_ping_fails(test_id));
        REQUIRE(actual_value.has_value());
        CHECK(*actual_value == expected_value);
    }

    SECTION("update_and_find_peer_disconnected_time") {
        runner.run(db.upsert_node_address(test_id, test_address));
        auto expected_value = std::chrono::system_clock::system_clock::now();
        runner.run(db.update_peer_disconnected_time(test_id, expected_value));
        auto actual_value = runner.run(db.find_peer_disconnected_time(test_id));
        REQUIRE(actual_value.has_value());
        CHECK(std::chrono::duration_cast<std::chrono::seconds>(*actual_value - expected_value).count() == 0);
    }

    SECTION("update_and_find_peer_is_useless") {
        runner.run(db.upsert_node_address(test_id, test_address));
        auto expected_value = true;
        runner.run(db.update_peer_is_useless(test_id, expected_value));
        auto actual_value = runner.run(db.find_peer_is_useless(test_id));
        REQUIRE(actual_value.has_value());
        CHECK(*actual_value == expected_value);
    }

    SECTION("update_and_find_distance") {
        runner.run(db.upsert_node_address(test_id, test_address));
        size_t expected_value = 123;
        runner.run(db.update_distance(test_id, expected_value));
        auto actual_value = runner.run(db.find_distance(test_id));
        REQUIRE(actual_value.has_value());
        CHECK(*actual_value == expected_value);
    }

    SECTION("update_and_find_enr_seq_num") {
        runner.run(db.upsert_node_address(test_id, test_address));
        size_t expected_value = 123;
        runner.run(db.update_enr_seq_num(test_id, expected_value));
        auto actual_value = runner.run(db.find_enr_seq_num(test_id));
        REQUIRE(actual_value.has_value());
        CHECK(*actual_value == expected_value);
    }

    SECTION("update_and_find_eth1_fork_id") {
        runner.run(db.upsert_node_address(test_id, test_address));
        Bytes expected_value = {1, 2, 3};
        runner.run(db.update_eth1_fork_id(test_id, expected_value));
        auto actual_value = runner.run(db.find_eth1_fork_id(test_id));
        REQUIRE(actual_value.has_value());
        CHECK(*actual_value == expected_value);

        runner.run(db.update_eth1_fork_id(test_id, std::nullopt));
        auto actual_value_null = runner.run(db.find_eth1_fork_id(test_id));
        CHECK_FALSE(actual_value_null.has_value());
    }

    SECTION("find_ping_candidates.default") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        auto results = runner.run(db.find_ping_candidates(now, 1));
        REQUIRE_FALSE(results.empty());
        CHECK(results[0] == test_id);
    }

    SECTION("find_ping_candidates.next_ping_time") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_next_ping_time(test_id, now));

        auto results = runner.run(db.find_ping_candidates(now - 1h, 1));
        CHECK(results.empty());

        auto results2 = runner.run(db.find_ping_candidates(now + 1h, 1));
        REQUIRE_FALSE(results2.empty());
        CHECK(results2[0] == test_id);
    }

    SECTION("find_ping_candidates.peer_is_useless") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));

        runner.run(db.update_peer_is_useless(test_id, true));
        auto results = runner.run(db.find_ping_candidates(now, 1));
        CHECK(results.empty());

        runner.run(db.update_peer_is_useless(test_id, false));
        auto results2 = runner.run(db.find_ping_candidates(now, 1));
        REQUIRE_FALSE(results2.empty());
        CHECK(results2[0] == test_id);
    }

    SECTION("find_useful_nodes.default") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));
        auto results = runner.run(db.find_useful_nodes(now - 1h, 1));
        REQUIRE_FALSE(results.empty());
        CHECK(results[0] == test_id);
    }

    SECTION("find_useful_nodes.min_pong_time") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));

        auto min_pong_time = now + 1h;
        auto results = runner.run(db.find_useful_nodes(min_pong_time, 1));
        CHECK(results.empty());

        auto min_pong_time2 = now - 1h;
        auto results2 = runner.run(db.find_useful_nodes(min_pong_time2, 1));
        REQUIRE_FALSE(results2.empty());
        CHECK(results2[0] == test_id);
    }

    SECTION("find_useful_nodes.peer_is_useless") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));

        runner.run(db.update_peer_is_useless(test_id, true));
        auto results = runner.run(db.find_useful_nodes(now - 1h, 1));
        CHECK(results.empty());

        runner.run(db.update_peer_is_useless(test_id, false));
        auto results2 = runner.run(db.find_useful_nodes(now - 1h, 1));
        REQUIRE_FALSE(results2.empty());
        CHECK(results2[0] == test_id);
    }

    SECTION("find_peer_candidates.default") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));
        NodeDb::FindPeerCandidatesQuery query;
        query.limit = 1;
        auto results = runner.run(db.find_peer_candidates(query));
        REQUIRE_FALSE(results.empty());
        CHECK(results[0] == test_id);
    }

    SECTION("find_peer_candidates.min_pong_time") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));
        NodeDb::FindPeerCandidatesQuery query;
        query.limit = 1;

        query.min_pong_time = now + 1h;
        auto results = runner.run(db.find_peer_candidates(query));
        CHECK(results.empty());

        query.min_pong_time = now - 1h;
        auto results2 = runner.run(db.find_peer_candidates(query));
        REQUIRE_FALSE(results2.empty());
        CHECK(results2[0] == test_id);
    }

    SECTION("find_peer_candidates.max_peer_disconnected_time") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));
        runner.run(db.update_peer_disconnected_time(test_id, now));
        NodeDb::FindPeerCandidatesQuery query;
        query.limit = 1;

        query.max_peer_disconnected_time = now - 1h;
        auto results = runner.run(db.find_peer_candidates(query));
        CHECK(results.empty());

        query.max_peer_disconnected_time = now + 1h;
        auto results2 = runner.run(db.find_peer_candidates(query));
        REQUIRE_FALSE(results2.empty());
        CHECK(results2[0] == test_id);
    }

    SECTION("find_peer_candidates.max_taken_time") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));
        runner.run(db.mark_taken_peer_candidates({test_id}, now));
        NodeDb::FindPeerCandidatesQuery query;
        query.limit = 1;

        query.max_taken_time = now - 1h;
        auto results = runner.run(db.find_peer_candidates(query));
        CHECK(results.empty());

        query.max_taken_time = now + 1h;
        auto results2 = runner.run(db.find_peer_candidates(query));
        REQUIRE_FALSE(results2.empty());
        CHECK(results2[0] == test_id);
    }

    SECTION("find_peer_candidates.peer_is_useless") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));
        NodeDb::FindPeerCandidatesQuery query;
        query.limit = 1;

        runner.run(db.update_peer_is_useless(test_id, true));
        auto results = runner.run(db.find_peer_candidates(query));
        CHECK(results.empty());

        runner.run(db.update_peer_is_useless(test_id, false));
        auto results2 = runner.run(db.find_peer_candidates(query));
        REQUIRE_FALSE(results2.empty());
        CHECK(results2[0] == test_id);
    }

    SECTION("find_peer_candidates.exclude_ids") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));
        NodeDb::FindPeerCandidatesQuery query;
        query.limit = 1;

        query.exclude_ids = {test_id};
        auto results = runner.run(db.find_peer_candidates(query));
        CHECK(results.empty());

        query.exclude_ids.clear();
        auto results2 = runner.run(db.find_peer_candidates(query));
        REQUIRE_FALSE(results2.empty());
        CHECK(results2[0] == test_id);
    }

    SECTION("mark_taken_peer_candidates") {
        NodeId test_id2 = NodeId::deserialize_hex("24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d");
        NodeAddress test_address2{
            ip::make_address("10.0.1.17"),
            30304,
            30303,
        };

        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.upsert_node_address(test_id2, test_address2));

        auto expected_value = std::chrono::system_clock::system_clock::now();
        runner.run(db.mark_taken_peer_candidates({test_id, test_id2}, expected_value));
    }

    SECTION("take_peer_candidates.empty") {
        auto now = std::chrono::system_clock::system_clock::now();
        NodeDb::FindPeerCandidatesQuery query;
        auto results = runner.run(db.take_peer_candidates(query, now));
        CHECK(results.empty());
    }

    SECTION("find_lookup_candidates.default") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));
        NodeDb::FindLookupCandidatesQuery query;
        query.limit = 1;
        auto results = runner.run(db.find_lookup_candidates(query));
        REQUIRE_FALSE(results.empty());
        CHECK(results[0] == test_id);
    }

    SECTION("find_lookup_candidates.min_pong_time") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));
        NodeDb::FindLookupCandidatesQuery query;
        query.limit = 1;

        query.min_pong_time = now + 1h;
        auto results = runner.run(db.find_lookup_candidates(query));
        CHECK(results.empty());

        query.min_pong_time = now - 1h;
        auto results2 = runner.run(db.find_lookup_candidates(query));
        REQUIRE_FALSE(results2.empty());
        CHECK(results2[0] == test_id);
    }

    SECTION("find_lookup_candidates.max_lookup_time") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));
        runner.run(db.mark_taken_lookup_candidates({test_id}, now));
        NodeDb::FindLookupCandidatesQuery query;
        query.limit = 1;

        query.max_lookup_time = now - 1h;
        auto results = runner.run(db.find_lookup_candidates(query));
        CHECK(results.empty());

        query.max_lookup_time = now + 1h;
        auto results2 = runner.run(db.find_lookup_candidates(query));
        REQUIRE_FALSE(results2.empty());
        CHECK(results2[0] == test_id);
    }

    SECTION("find_lookup_candidates.peer_is_useless") {
        auto now = std::chrono::system_clock::system_clock::now();
        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.update_last_pong_time(test_id, now));
        NodeDb::FindLookupCandidatesQuery query;
        query.limit = 1;

        runner.run(db.update_peer_is_useless(test_id, true));
        auto results = runner.run(db.find_lookup_candidates(query));
        CHECK(results.empty());

        runner.run(db.update_peer_is_useless(test_id, false));
        auto results2 = runner.run(db.find_lookup_candidates(query));
        REQUIRE_FALSE(results2.empty());
        CHECK(results2[0] == test_id);
    }

    SECTION("mark_taken_lookup_candidates") {
        NodeId test_id2 = NodeId::deserialize_hex("24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d");
        NodeAddress test_address2{
            ip::make_address("10.0.1.17"),
            30304,
            30303,
        };

        runner.run(db.upsert_node_address(test_id, test_address));
        runner.run(db.upsert_node_address(test_id2, test_address2));

        auto expected_value = std::chrono::system_clock::system_clock::now();
        runner.run(db.mark_taken_lookup_candidates({test_id, test_id2}, expected_value));
    }

    SECTION("take_lookup_candidates.empty") {
        auto now = std::chrono::system_clock::system_clock::now();
        NodeDb::FindLookupCandidatesQuery query;
        auto results = runner.run(db.take_lookup_candidates(query, now));
        CHECK(results.empty());
    }
}

}  // namespace silkworm::sentry::discovery::node_db
