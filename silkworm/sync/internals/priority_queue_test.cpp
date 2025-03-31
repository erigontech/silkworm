// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>

#include "header_chain.hpp"

namespace silkworm {

TEST_CASE("SetBasedPriorityQueue") {
    SetBasedPriorityQueue<int, std::greater<>> queue;
    queue.push(3);
    queue.push(2);
    queue.push(4);
    queue.push(1);

    SECTION("element ordering") {
        REQUIRE(queue.size() == 4);

        auto begin = queue.begin();
        CHECK(*begin == 4);
        CHECK(*(++begin) == 3);
        auto end = queue.end();
        CHECK(*(--end) == 1);
    }

    SECTION("in order removal") {
        REQUIRE(queue.size() == 4);

        CHECK(queue.top() == 4);
        queue.pop();
        CHECK(queue.top() == 3);
        queue.pop();
        CHECK(queue.top() == 2);
        queue.pop();
        CHECK(queue.top() == 1);
        queue.pop();

        CHECK(queue.empty());
        CHECK(queue.begin() == queue.end());
    }

    SECTION("erasing from the top") {
        REQUIRE(queue.size() == 4);

        auto top = queue.top();
        queue.erase(top);

        REQUIRE(queue.size() == 3);

        CHECK(queue.top() == 3);
        queue.pop();
        CHECK(queue.top() == 2);
        queue.pop();
        CHECK(queue.top() == 1);
        queue.pop();
    }

    SECTION("erasing in the middle") {
        queue.erase(2);

        REQUIRE(queue.size() == 3);

        CHECK(queue.top() == 4);
        queue.pop();
        CHECK(queue.top() == 3);
        queue.pop();
        CHECK(queue.top() == 1);
        queue.pop();
    }

    SECTION("containment") {
        CHECK(queue.contains(1));
        CHECK(queue.contains(2));
        CHECK(queue.contains(3));
        CHECK(queue.contains(4));
        CHECK(!queue.contains(5));
    }

    SECTION("updating items") {
        REQUIRE(queue.size() == 4);

        bool ok = queue.update(2, [](int& x) { x = 0; });
        CHECK(ok);

        CHECK(queue.top() == 4);
        queue.pop();
        CHECK(queue.top() == 3);
        queue.pop();
        CHECK(queue.top() == 1);
        queue.pop();
        CHECK(queue.top() == 0);
        queue.pop();
    }
}

TEST_CASE("SetBasedPriorityQueue - shared_ptr") {
    struct GreaterThan : public std::function<bool(std::shared_ptr<int>, std::shared_ptr<int>)> {
        bool operator()(const std::shared_ptr<int>& x, const std::shared_ptr<int>& y) const {
            return *x != *y ? *x > *y : x > y;  // operator <, when values are the same preserve identity
        }
    };

    SetBasedPriorityQueue<std::shared_ptr<int>, GreaterThan> queue;
    queue.push(std::make_shared<int>(3));
    queue.push(std::make_shared<int>(2));
    queue.push(std::make_shared<int>(4));
    queue.push(std::make_shared<int>(1));

    REQUIRE(queue.size() == 4);

    SECTION("updating items") {
        auto top = queue.top();
        bool updated = queue.update(top, [](auto& x) { *x = 0; });
        CHECK(updated);
        CHECK(*queue.top() == 3);
        auto end = queue.end();
        CHECK(**(--end) == 0);
    }
}

TEST_CASE("Oldest_First_Anchor_Queue") {
    using namespace std::literals::chrono_literals;
    BlockHeader dummy_header;
    time_point_t now = std::chrono::system_clock::now();
    PeerId dummy_peer_id{byte_ptr_cast("dummy-peer-id")};

    OldestFirstAnchorQueue queue;

    auto anchor = std::make_shared<Anchor>(dummy_header, dummy_peer_id);
    anchor->block_num = 1;
    anchor->timestamp = now;
    queue.push(anchor);

    anchor = std::make_shared<Anchor>(dummy_header, dummy_peer_id);
    anchor->block_num = 3;
    anchor->timestamp = now;
    queue.push(anchor);

    anchor = std::make_shared<Anchor>(dummy_header, dummy_peer_id);
    anchor->block_num = 2;
    anchor->timestamp = now + 2s;
    queue.push(anchor);
    auto anchor2 = anchor;

    anchor = std::make_shared<Anchor>(dummy_header, dummy_peer_id);
    anchor->block_num = 4;
    anchor->timestamp = now + 4s;
    queue.push(anchor);

    REQUIRE(queue.size() == 4);

    SECTION("element ordering") {
        REQUIRE(queue.size() == 4);

        REQUIRE((queue.top()->timestamp == now && queue.top()->block_num == 1));
        queue.pop();
        REQUIRE((queue.top()->timestamp == now && queue.top()->block_num == 3));
        queue.pop();
        REQUIRE(queue.top()->timestamp == now + 2s);
        queue.pop();
        REQUIRE(queue.top()->timestamp == now + 4s);
        queue.pop();

        CHECK(queue.empty());
    }

    SECTION("in order iterating") {
        auto begin = queue.begin();
        auto& elem1 = *begin;
        CHECK((elem1->timestamp == now && elem1->block_num == 1));
        auto& elem2 = *(++begin);
        CHECK((elem2->timestamp == now && elem2->block_num == 3));
        auto& elem3 = *(++begin);
        CHECK((elem3->timestamp == now + 2s));
        auto& elem4 = *(++begin);
        CHECK((elem4->timestamp == now + 4s));

        auto end = queue.end();
        auto& elem4bis = *(--end);
        CHECK((elem4bis->timestamp == now + 4s));
    }

    SECTION("updating items") {
        REQUIRE(queue.size() == 4);

        auto top_anchor = queue.top();
        queue.update(top_anchor, [&](auto& a) { a->timestamp = now + 5s; });

        CHECK((queue.top()->timestamp == now && queue.top()->block_num == 3));
        REQUIRE(queue.size() == 4);
        queue.pop();
        queue.pop();
        queue.pop();
        CHECK((queue.top()->timestamp == now + 5s && queue.top()->block_num == 1));
    }

    SECTION("erase an element") {
        REQUIRE(queue.size() == 4);

        auto top_anchor = queue.top();
        queue.erase(top_anchor);
        CHECK(queue.size() == 3);
        CHECK((queue.top()->timestamp == now && queue.top()->block_num == 3));

        queue.erase(anchor2);
        CHECK(queue.size() == 2);
        CHECK((queue.top()->timestamp == now && queue.top()->block_num == 3));
        queue.pop();
        CHECK(queue.top()->timestamp == now + 4s);
    }
}

TEST_CASE("Oldest_First_Anchor_Queue - siblings handling") {
    using namespace std::literals::chrono_literals;
    time_point_t now = std::chrono::system_clock::now();
    PeerId dummy_peer_id{byte_ptr_cast("dummy-peer-id")};

    BlockHeader dummy_header;

    auto anchor1 = std::make_shared<Anchor>(dummy_header, dummy_peer_id);
    anchor1->block_num = 1;
    anchor1->timestamp = now;

    auto anchor2 = std::make_shared<Anchor>(dummy_header, dummy_peer_id);
    anchor2->block_num = 1;  // same block number, it is a sibling
    anchor2->timestamp = now;

    OldestFirstAnchorQueue queue;

    queue.push(anchor1);
    CHECK(queue.size() == 1);
    queue.push(anchor2);  // add a sibling with different identity
    CHECK(queue.size() == 2);
    queue.erase(anchor2);  // erase only 1 element using identity, not block number
    CHECK(queue.size() == 1);
    queue.push(anchor1);       // add the same object, same identity
    CHECK(queue.size() == 1);  // should not add it
}

TEST_CASE("Oldest_First_Link_Queue") {
    using namespace std::literals::chrono_literals;
    BlockHeader dummy_header;
    bool persisted = true;

    OldestFirstLinkQueue queue;

    auto link1 = std::make_shared<Link>(dummy_header, persisted);
    link1->block_num = 1;

    auto link2 = std::make_shared<Link>(dummy_header, persisted);
    link2->block_num = 2;

    auto link3 = std::make_shared<Link>(dummy_header, persisted);
    link3->block_num = 3;

    auto link4 = std::make_shared<Link>(dummy_header, persisted);
    link4->block_num = 4;

    queue.push(link1);
    queue.push(link4);
    queue.push(link2);
    queue.push(link3);

    SECTION("element ordering") {
        REQUIRE(queue.size() == 4);

        REQUIRE(queue.top()->block_num == 1);
        queue.pop();
        REQUIRE(queue.top()->block_num == 2);
        queue.pop();
        REQUIRE(queue.top()->block_num == 3);
        queue.pop();
        REQUIRE(queue.top()->block_num == 4);
        queue.pop();

        REQUIRE(queue.empty());
    }

    SECTION("erase an element") {
        REQUIRE(queue.size() == 4);

        auto top_link = queue.top();
        queue.erase(top_link);
        REQUIRE(queue.size() == 3);
        REQUIRE(queue.top()->block_num == 2);

        queue.erase(link3);
        REQUIRE(queue.size() == 2);
        REQUIRE(queue.top()->block_num == 2);
        queue.pop();
        REQUIRE(queue.top()->block_num == 4);
    }

    SECTION("siblings, same identity") {
        REQUIRE(queue.size() == 4);

        queue.push(link1);  // again, same identity

        CHECK(queue.size() == 4);
        bool link1_present = queue.contains(link1);
        REQUIRE(link1_present == true);
    }

    SECTION("siblings, different identity") {
        REQUIRE(queue.size() == 4);

        auto link1b = std::make_shared<Link>(dummy_header, persisted);
        link1b->block_num = 1;
        link1b->persisted = !persisted;

        bool link1b_present = queue.contains(link1b);
        REQUIRE(link1b_present == false);

        queue.push(link1b);  // again, different identity

        REQUIRE(queue.size() == 5);
        bool link1_present = queue.contains(link1);
        REQUIRE(link1_present == true);
        link1b_present = queue.contains(link1b);
        REQUIRE(link1b_present == true);
    }
}

TEST_CASE("Oldest_First_Link_Map") {
    using namespace std::literals::chrono_literals;
    BlockHeader dummy_header;
    bool persisted = true;

    OldestFirstLinkMap queue;

    auto link1 = std::make_shared<Link>(dummy_header, persisted);
    link1->block_num = 1;
    queue.push(link1);

    auto link4 = std::make_shared<Link>(dummy_header, persisted);
    link4->block_num = 4;
    queue.push(link4);

    auto link3 = std::make_shared<Link>(dummy_header, persisted);
    link3->block_num = 3;
    queue.push(link3);

    auto link2 = std::make_shared<Link>(dummy_header, persisted);
    link2->block_num = 2;
    queue.push(link2);

    SECTION("element ordering") {
        REQUIRE(queue.size() == 4);

        REQUIRE(queue.top()->block_num == 1);  // top
        queue.pop();
        REQUIRE(queue.top()->block_num == 2);
        queue.pop();
        REQUIRE(queue.top()->block_num == 3);
        queue.pop();
        REQUIRE(queue.top()->block_num == 4);
        queue.pop();

        REQUIRE(queue.empty());
    }

    SECTION("erase an element") {
        REQUIRE(queue.size() == 4);

        auto top_link = queue.top();
        queue.erase(top_link);
        REQUIRE(queue.size() == 3);
        REQUIRE(queue.top()->block_num == 2);

        queue.erase(link3);
        REQUIRE(queue.size() == 2);
        REQUIRE(queue.top()->block_num == 2);
        queue.pop();
        REQUIRE(queue.top()->block_num == 4);
    }

    SECTION("siblings, same identity") {
        REQUIRE(queue.size() == 4);

        queue.push(link1);  // again, same identity

        REQUIRE(queue.size() == 5);
        bool link1_present = queue.contains(link1);
        REQUIRE(link1_present == true);

        auto [a, c] = queue.equal_range(BlockNum{1});
        REQUIRE(a != queue.end());
        REQUIRE(c != queue.end());
        REQUIRE(a != c);
        REQUIRE(*a != *c);
        REQUIRE(a->first == 1);
        REQUIRE(a->second->block_num == 1);
        auto b = a;
        ++b;
        REQUIRE(a != b);    // different iterator
        REQUIRE(*a == *b);  // same identity
        REQUIRE(b->first == 1);
        REQUIRE(b->second->block_num == 1);
        REQUIRE(++b == c);
    }

    SECTION("siblings, different identity") {
        REQUIRE(queue.size() == 4);

        auto link1b = std::make_shared<Link>(dummy_header, persisted);
        link1b->block_num = 1;
        link1b->persisted = !persisted;
        queue.push(link1b);  // again, different identity

        REQUIRE(queue.size() == 5);
        bool link1_present = queue.contains(link1);
        REQUIRE(link1_present == true);
        bool link1b_present = queue.contains(link1b);
        REQUIRE(link1b_present == true);

        auto [a, c] = queue.equal_range(BlockNum{1});
        REQUIRE(a != queue.end());
        REQUIRE(c != queue.end());
        REQUIRE(a != c);
        REQUIRE(*a != *c);
        REQUIRE(a->first == 1);
        REQUIRE(a->second->block_num == 1);
        auto b = a;
        ++b;
        REQUIRE(a != b);    // different iterator
        REQUIRE(*a != *b);  // different identity
        REQUIRE(b->first == 1);
        REQUIRE(b->second->block_num == 1);
        REQUIRE(++b == c);
    }
}
}  // namespace silkworm