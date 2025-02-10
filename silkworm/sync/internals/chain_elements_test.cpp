/*
   Copyright 2022 The Silkworm Authors

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

#include "chain_elements.hpp"

#include <algorithm>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>

namespace silkworm {

TEST_CASE("links") {
    bool persisted = false;

    std::array<BlockHeader, 5> headers;

    for (size_t i = 1; i < headers.size(); ++i) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i * 100;  // improve!
        headers[i].parent_hash = headers[i - 1].hash();
    }

    Link link1(headers[1], persisted);

    auto link2 = std::make_shared<Link>(headers[2], persisted);
    auto link3 = std::make_shared<Link>(headers[3], persisted);

    SECTION("construction") {
        REQUIRE(*(link1.header) == headers[1]);
        REQUIRE(link1.block_num == headers[1].number);
        REQUIRE(link1.hash == headers[1].hash());
        REQUIRE(link1.persisted == persisted);
        REQUIRE(link1.preverified == false);
        REQUIRE(link1.next.empty());

        headers[1].number = 100;        // only for the following test
        REQUIRE(link1.block_num == 1);  // link1 has a copy of headers[1]
        headers[1].number = 1;          // ok
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
    PeerId peer_id{byte_ptr_cast("dummy")};
    bool persisted = false;

    std::array<BlockHeader, 5> headers;

    for (size_t i = 1; i < headers.size(); ++i) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i * 100;  // improve!
        headers[i].parent_hash = headers[i - 1].hash();
    }

    Anchor anchor(headers[1], peer_id);

    std::array<std::shared_ptr<Link>, 5> links;

    for (size_t i = 1; i < links.size(); ++i) {  // skip first header for simplicity
        links[i] = std::make_shared<Link>(headers[i], persisted);
    }

    SECTION("construction") {
        REQUIRE(anchor.parent_hash == headers[1].parent_hash);
        REQUIRE(anchor.block_num == headers[1].number);
        REQUIRE(anchor.last_link_block_num == headers[1].number);
        REQUIRE(anchor.peer_id == peer_id);
        REQUIRE(anchor.links.empty());
        REQUIRE(anchor.chain_length() == 1);
    }

    SECTION("children") {
        REQUIRE(anchor.find_child(headers[1].hash()) == anchor.links.end());
        REQUIRE(anchor.has_child(headers[1].hash()) == false);

        for (size_t i = 1; i <= 3; ++i) {
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

TEST_CASE("segments") {
    std::vector<BlockHeader> headers(10);
    for (size_t i = 0; i < headers.size(); ++i) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i * 100;  // improve!
        headers[i].parent_hash = (i != 0) ? headers[i - 1].hash() : evmc::bytes32{0};
    }

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();
    REQUIRE(segments.size() == 1);
    REQUIRE(penalty == kNoPenalty);

    Segment segment = segments[0];
    REQUIRE(segment.lowest_header()->number == headers[0].number);
    REQUIRE(segment.max_header()->number == headers[headers.size() - 1].number);
    REQUIRE(segment[0]->number == headers[headers.size() - 1].number);  // segment is reversed
    REQUIRE(segment[segment.size() - 1]->number == headers[0].number);  // "

    size_t start = 2;
    size_t end = 5;
    auto start_num = segment[start]->number;
    auto end_num = segment[end - 1]->number;

    Segment::Slice segment_slice = segment.slice(start, end);
    REQUIRE(segment_slice.size() == end - start);
    REQUIRE(segment_slice[0]->number == start_num);                       // headers in segment are ordered from max to lowest
    REQUIRE(segment_slice[segment_slice.size() - 1]->number == end_num);  // "

    segment.remove_headers_higher_than(3);
    REQUIRE(segment.size() == 4);
    REQUIRE(segment.lowest_header()->number == headers[0].number);
    REQUIRE(segment.max_header()->number == 3);
    REQUIRE(segment[0]->number == 3);
    REQUIRE(segment[segment.size() - 1]->number == headers[0].number);
}

}  // namespace silkworm
