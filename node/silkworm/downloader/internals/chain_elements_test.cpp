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

#include "chain_elements.hpp"

namespace silkworm {

TEST_CASE("links") {
    PeerId peer_id{"dummy"};
    bool persisted = false;

    std::array<BlockHeader, 5> headers;

    for (size_t i = 1; i < headers.size(); i++) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i * 100;  // improve!
        headers[i].parent_hash = headers[i - 1].hash();
    }

    Link link1(headers[1], persisted);

    auto link2 = std::make_shared<Link>(headers[2], persisted);
    auto link3 = std::make_shared<Link>(headers[3], persisted);

    SECTION("construction") {
        REQUIRE(*(link1.header) == headers[1]);
        REQUIRE(link1.blockHeight == headers[1].number);
        REQUIRE(link1.hash == headers[1].hash());
        REQUIRE(link1.persisted == persisted);
        REQUIRE(link1.preverified == false);
        REQUIRE(link1.next.empty());

        headers[1].number = 100; // only for the following test
        REQUIRE(link1.blockHeight == 1); // link1 has a copy of headers[1]
        headers[1].number = 1; // ok
    }

    SECTION("children") {
        REQUIRE(link1.find_child(headers[1].hash()) == link1.next.end());
        REQUIRE(link1.has_child(headers[1].hash()) == false);

        link1.next.push_back(link2);
        link1.next.push_back(link3);
        REQUIRE(link1.next.size() == 2);

        bool link2_present = link1.has_child(link2->hash);
        REQUIRE(link2_present);
        bool link3_present = link1.has_child(link3->hash);
        REQUIRE(link3_present);
        bool link4_present = link1.has_child(headers[4].hash());
        REQUIRE(!link4_present);

        auto link2_it = link1.find_child(link2->hash);
        REQUIRE(link2_it != link1.next.end());
        auto link4_it = link1.find_child(headers[4].hash());
        REQUIRE(link4_it == link1.next.end());

        link1.remove_child(*link3);
        REQUIRE(link1.next.size() == 1);
        link3_present = link1.has_child(link3->hash);
        REQUIRE(!link3_present);
        auto link3_it = link1.find_child(link3->hash);
        REQUIRE(link3_it == link1.next.end());
    }
}

TEST_CASE("anchors") {
    PeerId peer_id{"dummy"};
    bool persisted = false;

    std::array<BlockHeader, 5> headers;

    for (size_t i = 1; i < headers.size(); i++) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i * 100;  // improve!
        headers[i].parent_hash = headers[i - 1].hash();
    }

    Anchor anchor(headers[1], peer_id);

    std::array<std::shared_ptr<Link>, 5> links;

    for (size_t i = 1; i < links.size(); i++) {  // skip first header for simplicity
        links[i] = std::make_shared<Link>(headers[i], persisted);
    }

    SECTION("construction") {
        REQUIRE(anchor.parentHash == headers[1].parent_hash);
        REQUIRE(anchor.blockHeight == headers[1].number);
        REQUIRE(anchor.lastLinkHeight == headers[1].number);
        REQUIRE(anchor.peerId == peer_id);
        REQUIRE(anchor.links.empty());
        REQUIRE(anchor.chainLength() == 1);
    }

    SECTION("children") {
        REQUIRE(anchor.find_child(headers[1].hash()) == anchor.links.end());
        REQUIRE(anchor.has_child(headers[1].hash()) == false);

        for(size_t i = 1; i <= 3; i++) {
            anchor.links.push_back(links[i]);
        }

        bool link2_present = anchor.has_child(links[2]->hash);
        REQUIRE(link2_present);
        bool link4_present = anchor.has_child(links[4]->hash);
        REQUIRE(!link4_present);

        auto link2_it = anchor.find_child(links[2]->hash);
        REQUIRE(link2_it != anchor.links.end());
        auto link4_it = anchor.find_child(links[4]->hash);
        REQUIRE(link4_it == anchor.links.end());

        anchor.remove_child(*links[3]);
        REQUIRE(anchor.links.size() == 2);
        auto link3_present = anchor.has_child(links[3]->hash);
        REQUIRE(!link3_present);
        auto link3_it = anchor.find_child(links[3]->hash);
        REQUIRE(link3_it == anchor.links.end());
    }

}

}
