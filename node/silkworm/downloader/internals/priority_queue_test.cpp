/*
    Copyright 2020 The Silkworm Authors

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

#include <algorithm>

#include <catch2/catch.hpp>

#include "working_chain.hpp"

namespace silkworm {

TEST_CASE("heap_based_priority_queue - element ordering") {
    heap_based_priority_queue<int> queue;
    queue.push(3);
    queue.push(2);
    queue.push(4);
    queue.push(1);

    REQUIRE(queue.size() == 4);

    REQUIRE(queue.top() == 4);
    queue.pop();
    REQUIRE(queue.top() == 3);
    queue.pop();
    REQUIRE(queue.top() == 2);
    queue.pop();
    REQUIRE(queue.top() == 1);
    queue.pop();

    REQUIRE(queue.size() == 0);
}

TEST_CASE("Oldest_First_Anchor_Queue") {
    using namespace std::literals::chrono_literals;
    BlockHeader dummy_header;
    time_point_t now = std::chrono::system_clock::now();

    OldestFirstAnchorQueue queue;

    auto anchor = std::make_shared<Anchor>(dummy_header, "dummy-peer-id");
    anchor->blockHeight = 1;
    anchor->timestamp = now;
    queue.push(anchor);

    anchor = std::make_shared<Anchor>(dummy_header, "dummy-peer-id");
    anchor->blockHeight = 3;
    anchor->timestamp = now;
    queue.push(anchor);

    anchor = std::make_shared<Anchor>(dummy_header, "dummy-peer-id");
    anchor->blockHeight = 2;
    anchor->timestamp = now + 2s;
    queue.push(anchor);
    auto anchor2 = anchor;

    anchor = std::make_shared<Anchor>(dummy_header, "dummy-peer-id");
    anchor->blockHeight = 4;
    anchor->timestamp = now + 4s;
    queue.push(anchor);

    REQUIRE(queue.size() == 4);

    SECTION("element ordering") {
        REQUIRE(queue.size() == 4);

        REQUIRE((queue.top()->timestamp == now && queue.top()->blockHeight == 1));
        queue.pop();
        REQUIRE((queue.top()->timestamp == now && queue.top()->blockHeight == 3));
        queue.pop();
        REQUIRE(queue.top()->timestamp == now + 2s);
        queue.pop();
        REQUIRE(queue.top()->timestamp == now + 4s);
        queue.pop();

        REQUIRE(queue.size() == 0);
    }

    SECTION("fix the queue") {
        REQUIRE(queue.size() == 4);

        auto top_anchor = queue.top();
        top_anchor->timestamp = now + 5s;

        // top anchor changed but queue is broken
        REQUIRE((queue.top()->timestamp == now + 5s && queue.top()->blockHeight == 1));

        // let fix it
        queue.fix();
        REQUIRE(
            (queue.top()->timestamp == now && queue.top()->blockHeight == 3));  // now 2nd anchor is the new top anchor
        REQUIRE(queue.size() == 4);
        queue.pop();
        queue.pop();
        queue.pop();
        REQUIRE((queue.top()->timestamp == now + 5s && queue.top()->blockHeight == 1));  // now top anchor is at bottom
    }

    SECTION("erase an element") {
        REQUIRE(queue.size() == 4);

        auto top_anchor = queue.top();
        queue.erase(top_anchor);
        REQUIRE(queue.size() == 3);
        REQUIRE((queue.top()->timestamp == now && queue.top()->blockHeight == 3));

        queue.erase(anchor2);
        REQUIRE(queue.size() == 2);
        REQUIRE((queue.top()->timestamp == now && queue.top()->blockHeight == 3));
        queue.pop();
        REQUIRE(queue.top()->timestamp == now + 4s);
    }
}

TEST_CASE("Youngest_First_Link_Queue") {
    using namespace std::literals::chrono_literals;
    BlockHeader dummy_header;
    bool persisted = false;

    YoungestFirstLinkQueue queue;

    auto link = std::make_shared<Link>(dummy_header, persisted);
    link->blockHeight = 1;
    queue.push(link);

    link = std::make_shared<Link>(dummy_header, persisted);
    link->blockHeight = 4;
    queue.push(link);

    link = std::make_shared<Link>(dummy_header, persisted);
    link->blockHeight = 3;
    queue.push(link);

    link = std::make_shared<Link>(dummy_header, persisted);
    link->blockHeight = 2;
    queue.push(link);

    auto link2 = link;  // copy

    SECTION("element ordering") {
        REQUIRE(queue.size() == 4);

        REQUIRE(queue.top()->blockHeight == 4);
        queue.pop();
        REQUIRE(queue.top()->blockHeight == 3);
        queue.pop();
        REQUIRE(queue.top()->blockHeight == 2);
        queue.pop();
        REQUIRE(queue.top()->blockHeight == 1);
        queue.pop();

        REQUIRE(queue.size() == 0);
    }

    SECTION("erase an element") {
        REQUIRE(queue.size() == 4);

        auto top_link = queue.top();
        queue.erase(top_link);
        REQUIRE(queue.size() == 3);
        REQUIRE(queue.top()->blockHeight == 3);

        queue.erase(link2);
        REQUIRE(queue.size() == 2);
        REQUIRE(queue.top()->blockHeight == 3);
        queue.pop();
        REQUIRE(queue.top()->blockHeight == 1);
    }
}

TEST_CASE("Oldest_First_Link_Queue") {
    using namespace std::literals::chrono_literals;
    BlockHeader dummy_header;
    bool persisted = true;

    OldestFirstLinkQueue queue;

    auto link = std::make_shared<Link>(dummy_header, persisted);
    link->blockHeight = 1;
    queue.push(link);

    link = std::make_shared<Link>(dummy_header, persisted);
    link->blockHeight = 4;
    queue.push(link);

    link = std::make_shared<Link>(dummy_header, persisted);
    link->blockHeight = 3;
    queue.push(link);

    link = std::make_shared<Link>(dummy_header, persisted);
    link->blockHeight = 2;
    queue.push(link);

    SECTION("element ordering") {
        REQUIRE(queue.size() == 4);

        REQUIRE(queue.top()->blockHeight == 1);
        queue.pop();
        REQUIRE(queue.top()->blockHeight == 2);
        queue.pop();
        REQUIRE(queue.top()->blockHeight == 3);
        queue.pop();
        REQUIRE(queue.top()->blockHeight == 4);
        queue.pop();

        REQUIRE(queue.size() == 0);
    }

    /* no erase method
    SECTION("erase an element") {
        REQUIRE(queue.size() == 4);

        auto top_link = queue.top();
        queue.erase(top_link);
        REQUIRE(queue.size() == 3);
        REQUIRE(queue.top()->blockHeight == 3);

        queue.erase(link2);
        REQUIRE(queue.size() == 2);
        REQUIRE(queue.top()->blockHeight == 3);
        queue.pop();
        REQUIRE(queue.top()->blockHeight == 1);
    }
    */
}
}  // namespace silkworm