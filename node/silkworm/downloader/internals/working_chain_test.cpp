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

#include "working_chain.hpp"

#include <algorithm>

#include <catch2/catch.hpp>

namespace silkworm {
// Useful definitions
// ----------------------------------------------------------------------------

class WorkingChain_ForTest : public WorkingChain {
  public:  // publication of internal members to test methods functioning
    using WorkingChain::anchorQueue_;
    using WorkingChain::anchors_;
    using WorkingChain::linkQueue_;
    using WorkingChain::links_;
    using WorkingChain::WorkingChain;
};

/*
    long int difficulty(const BlockHeader& header, const BlockHeader& parent) {
        return static_cast<long int>(parent.difficulty) +
               static_cast<long int>(parent.difficulty / 2048) * std::max(1 - static_cast<long int>(header.timestamp -
   parent.timestamp) / 10, -99L)
               + int(2^((header.number / 100000) - 2));
    }
*/
// TESTs related to HeaderList::split_into_segments
// ----------------------------------------------------------------------------

TEST_CASE("HeaderList - split_into_segments - No headers") {
    std::vector<BlockHeader> headers;

    auto headerList = HeaderList::make(headers);

    auto [segments, penalty] = headerList->split_into_segments();

    REQUIRE(segments.size() == 0);
    REQUIRE(penalty == Penalty::NoPenalty);
}

TEST_CASE("HeaderList - split_into_segments - Single header") {
    std::vector<BlockHeader> headers;
    BlockHeader header;
    header.number = 5;
    headers.push_back(header);

    auto headerList = HeaderList::make(headers);

    auto [segments, penalty] = headerList->split_into_segments();

    REQUIRE(segments.size() == 1);
    REQUIRE(penalty == Penalty::NoPenalty);
}

TEST_CASE("HeaderList - split_into_segments - Single header repeated twice") {
    std::vector<BlockHeader> headers;
    BlockHeader header;
    header.number = 5;
    headers.push_back(header);
    headers.push_back(header);

    auto headerList = HeaderList::make(headers);

    auto [segments, penalty] = headerList->split_into_segments();

    REQUIRE(segments.size() == 0);
    REQUIRE(penalty == Penalty::DuplicateHeaderPenalty);
}

TEST_CASE("HeaderList - split_into_segments - Two connected headers") {
    std::vector<BlockHeader> headers;

    BlockHeader header1;
    header1.number = 1;
    header1.difficulty = 10;
    headers.push_back(header1);

    BlockHeader header2;
    header2.number = 2;
    header2.difficulty = 1010;
    header2.parent_hash = header1.hash();
    headers.push_back(header2);

    auto headerList = HeaderList::make(headers);

    auto [segments, penalty] = headerList->split_into_segments();

    REQUIRE(penalty == Penalty::NoPenalty);
    REQUIRE(segments.size() == 1);                      // 1 segment
    REQUIRE(segments[0].size() == 2);                   // 2 headers
    REQUIRE(segments[0][0]->number == header2.number);  // the highest at the beginning
    REQUIRE(segments[0][1]->number == header1.number);
}

TEST_CASE("HeaderList - split_into_segments - Two connected headers with wrong numbers") {
    std::vector<BlockHeader> headers;

    BlockHeader header1;
    header1.number = 1;
    header1.difficulty = 10;
    headers.push_back(header1);

    BlockHeader header2;
    header2.number = 3;  // Expected block-number = 2
    header2.difficulty = 1010;
    header2.parent_hash = header1.hash();
    headers.push_back(header2);

    auto headerList = HeaderList::make(headers);

    auto [segments, penalty] = headerList->split_into_segments();

    REQUIRE(segments.size() == 0);
    REQUIRE(penalty == Penalty::WrongChildBlockHeightPenalty);
}

/* WrongChildDifficultyPenalty check is not implemented in Erigon/Silkworm code, so this test is commented
    TEST_CASE("HeaderList::split_into_segments - Two connected headers with wrong difficulty") {
        std::vector<BlockHeader> headers;

        BlockHeader header1;
        header1.number = 1;
        header1.difficulty = 10;
        headers.push_back(header1);

        BlockHeader header2;
        header2.number = 2;
        header2.difficulty = 2000; // Expected difficulty 10 + 1000 = 1010;
        header2.parent_hash = header1.hash();
        headers.push_back(header2);

        auto headerList = HeaderList::make(headers);

        auto [segments, penalty] = headerList->split_into_segments();

        REQUIRE(segments.size() == 0);
        REQUIRE(penalty == Penalty::WrongChildDifficultyPenalty);
    }
*/

/* input:
 *         h1 <----- h2
 *               |-- h3
 * output:
 *         3 segments: {h3}, {h2}, {h1}   (in this order)
 */
TEST_CASE("HeaderList - split_into_segments - Two headers connected to the third header") {
    std::vector<BlockHeader> headers;

    BlockHeader header1;
    header1.number = 1;
    header1.difficulty = 10;
    headers.push_back(header1);

    BlockHeader header2;
    header2.number = 2;
    header2.difficulty = 1010;
    header2.parent_hash = header1.hash();
    headers.push_back(header2);

    BlockHeader header3;
    header3.number = 2;
    header3.difficulty = 1010;
    header3.parent_hash = header1.hash();
    header3.extra_data =
        string_to_bytes("I'm different");  // To make sure the hash of h3 is different from the hash of h2
    headers.push_back(header3);

    auto headerList = HeaderList::make(headers);

    auto [segments, penalty] = headerList->split_into_segments();

    REQUIRE(penalty == Penalty::NoPenalty);
    REQUIRE(segments.size() == 3);                      // 3 segment
    REQUIRE(segments[0].size() == 1);                   // 1 headers
    REQUIRE(segments[1].size() == 1);                   // 1 headers
    REQUIRE(segments[2].size() == 1);                   // 1 headers
    REQUIRE(segments[2][0]->number == header1.number);  // expected h1 to be the root
    REQUIRE(segments[1][0]->number == header2.number);
    REQUIRE(segments[0][0]->number == header3.number);
}

TEST_CASE("HeaderList - split_into_segments - Same three headers, but in a reverse order") {
    std::vector<BlockHeader> headers;

    BlockHeader header1;
    header1.number = 1;
    header1.difficulty = 10;

    BlockHeader header2;
    header2.number = 2;
    header2.difficulty = 1010;
    header2.parent_hash = header1.hash();

    BlockHeader header3;
    header3.number = 2;
    header3.difficulty = 1010;
    header3.parent_hash = header1.hash();
    header3.extra_data =
        string_to_bytes("I'm different");  // To make sure the hash of h3 is different from the hash of h2

    headers.push_back(header3);
    headers.push_back(header2);
    headers.push_back(header1);

    auto headerList = HeaderList::make(headers);

    auto [segments, penalty] = headerList->split_into_segments();

    REQUIRE(penalty == Penalty::NoPenalty);
    REQUIRE(segments.size() == 3);                      // 3 segment
    REQUIRE(segments[0].size() == 1);                   // 1 headers
    REQUIRE(segments[2][0]->number == header1.number);  // expected h1 to be the root
    REQUIRE(segments[1][0]->number == header2.number);
    REQUIRE(segments[0][0]->number == header3.number);
}

/* input:
 *         (...) <----- h2
 *                  |-- h3
 * output:
 *         2 segments: {h3?}, {h2?}
 */
TEST_CASE("HeaderList - split_into_segments - Two headers not connected to each other") {
    std::vector<BlockHeader> headers;

    BlockHeader header1;
    header1.number = 1;
    header1.difficulty = 10;

    BlockHeader header2;
    header2.number = 2;
    header2.difficulty = 1010;
    header2.parent_hash = header1.hash();

    BlockHeader header3;
    header3.number = 2;
    header3.difficulty = 1010;
    header3.parent_hash = header1.hash();
    header3.extra_data =
        string_to_bytes("I'm different");  // To make sure the hash of h3 is different from the hash of h2

    headers.push_back(header3);
    headers.push_back(header2);

    auto headerList = HeaderList::make(headers);

    auto [segments, penalty] = headerList->split_into_segments();

    REQUIRE(penalty == Penalty::NoPenalty);
    REQUIRE(segments.size() == 2);              // 1 segment
    REQUIRE(segments[0].size() == 1);           // 1 header each
    REQUIRE(segments[1].size() == 1);           // 1 header each
    REQUIRE(segments[0][0] != segments[1][0]);  // different headers
}

/* input:
 *         h1 <----- h2 <----- h3
 * output:
 *        1 segment: {h3, h2, h1}   (with header in this order)
 */
TEST_CASE("HeaderList - split_into_segments - Three headers connected") {
    std::vector<BlockHeader> headers;

    BlockHeader header1;
    header1.number = 1;
    header1.difficulty = 10;
    headers.push_back(header1);

    BlockHeader header2;
    header2.number = 2;
    header2.difficulty = 1010;
    header2.parent_hash = header1.hash();
    headers.push_back(header2);

    BlockHeader header3;
    header3.number = 3;
    header3.difficulty = 101010;
    header3.parent_hash = header2.hash();
    headers.push_back(header3);

    auto headerList = HeaderList::make(headers);

    auto [segments, penalty] = headerList->split_into_segments();

    REQUIRE(penalty == Penalty::NoPenalty);
    REQUIRE(segments.size() == 1);                      // 1 segment
    REQUIRE(segments[0].size() == 3);                   // 3 headers
    REQUIRE(segments[0][0]->number == header3.number);  // expected h3 at the top
    REQUIRE(segments[0][1]->number == header2.number);
    REQUIRE(segments[0][2]->number == header1.number);  // expected h1 at the bottom
}

/* input:
 *         h1 <----- h2 <----- h3
 *                         |-- h4
 *
 * output:
 *        3 segments: {h3?}, {h4?}, {h2, h1}
 */
TEST_CASE("HeaderList - split_into_segments - Four headers connected") {
    std::vector<BlockHeader> headers;

    BlockHeader header1;
    header1.number = 1;
    header1.difficulty = 10;
    headers.push_back(header1);

    BlockHeader header2;
    header2.number = 2;
    header2.difficulty = 1010;
    header2.parent_hash = header1.hash();
    headers.push_back(header2);

    BlockHeader header3;
    header3.number = 3;
    header3.difficulty = 101010;
    header3.parent_hash = header2.hash();
    headers.push_back(header3);

    BlockHeader header4;
    header4.number = 3;
    header4.difficulty = 101010;
    header4.parent_hash = header2.hash();
    header4.extra_data = string_to_bytes("I'm different");
    headers.push_back(header4);

    auto headerList = HeaderList::make(headers);

    auto [segments, penalty] = headerList->split_into_segments();

    REQUIRE(penalty == Penalty::NoPenalty);
    REQUIRE(segments.size() == 3);     // 3 segment
    REQUIRE(segments[0].size() == 1);  // segment 0 - 1 headers
    REQUIRE(segments[1].size() == 1);  // segment 1 - 1 headers
    REQUIRE(segments[2].size() == 2);  // segment 2 - 2 headers
    REQUIRE(segments[2][0]->number == header2.number);
    REQUIRE(segments[2][1]->number == header1.number);
    REQUIRE(segments[0][0] != segments[1][0]);
}

// TESTs related to WorkingChain::accept_headers (segment manipulation: connect, extend_down, extend_up, new_anchor)
// -----------------------------------------------------------------------------------------------------------------

TEST_CASE("WorkingChain - process_segment - (1) simple chain") {
    using namespace std;

    WorkingChain_ForTest chain;
    chain.top_seen_block_height(1'000'000);

    PeerId peerId = "1";

    std::array<BlockHeader, 10> headers;

    for (size_t i = 1; i < headers.size(); i++) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i;  // improve!
        headers[i].parent_hash = headers[i - 1].hash();
    }

    /* chain status:
     *         void
     *
     * input:
     *         h1 <----- h2
     *         - triggering new_anchor
     * output:
     *         1 anchor, 2 links
     */
    INFO("new_anchor") {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[1], headers[2]}, peerId);

        REQUIRE(penalty == Penalty::NoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchorQueue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.linkQueue_.size() == 2);
        REQUIRE(chain.links_.size() == 2);

        auto anchor = chain.anchors_[headers[1].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parentHash == headers[1].parent_hash);
        REQUIRE(anchor->blockHeight == headers[1].number);
        REQUIRE(anchor->peerId == peerId);

        REQUIRE(anchor->links.size() == 1);
        REQUIRE(anchor->links[0]->hash == headers[1].hash());
        REQUIRE(anchor->links[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->hash == headers[2].hash());
    }

    /* chain status:
     *         h1 <----- h2
     *
     * input:
     *         (h2) <----- h3 <----- h4
     *         - triggering extend_up
     * output:
     *         1 anchor, 4 links
     */
    INFO("extend_up") {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[3], headers[4]}, peerId);

        REQUIRE(penalty == Penalty::NoPenalty);
        REQUIRE(requestMoreHeaders == false);
        REQUIRE(chain.anchorQueue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.linkQueue_.size() == 4);
        REQUIRE(chain.links_.size() == 4);

        auto anchor = chain.anchors_[headers[1].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parentHash == headers[1].parent_hash);
        REQUIRE(anchor->blockHeight == headers[1].number);
        REQUIRE(anchor->links.size() == 1);

        REQUIRE(anchor->links[0]->hash == headers[1].hash());
        REQUIRE(anchor->links[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->hash == headers[2].hash());
        REQUIRE(anchor->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->next[0]->hash == headers[3].hash());
        REQUIRE(anchor->links[0]->next[0]->next[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->next[0]->next[0]->hash == headers[4].hash());
        REQUIRE(anchor->links[0]->next[0]->next[0]->next[0]->next.size() == 0);
    }

    /* chain status:
     *         h1 <----- h2 <----- h3 <----- h4
     *
     * input:
     *         (h7) <----- h8 <----- h9  [h7 not provided]
     *         - triggering new_anchor
     * output:
     *         2 anchor, 6 links
     */
    INFO("new_anchor") {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[8], headers[9]}, peerId);

        REQUIRE(penalty == Penalty::NoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchorQueue_.size() == 2);
        REQUIRE(chain.anchors_.size() == 2);
        REQUIRE(chain.linkQueue_.size() == 6);
        REQUIRE(chain.links_.size() == 6);

        auto anchor1 = chain.anchors_[headers[1].parent_hash];
        REQUIRE(anchor1 != nullptr);
        REQUIRE(anchor1->parentHash == headers[1].parent_hash);
        REQUIRE(anchor1->blockHeight == headers[1].number);
        REQUIRE(anchor1->links.size() == 1);

        auto anchor2 = chain.anchors_[headers[8].parent_hash];
        REQUIRE(anchor2 != nullptr);
        REQUIRE(anchor2->parentHash == headers[8].parent_hash);
        REQUIRE(anchor2->blockHeight == headers[8].number);
        REQUIRE(anchor2->links.size() == 1);

        REQUIRE(anchor1->links[0]->hash == headers[1].hash());
        REQUIRE(anchor1->links[0]->next.size() == 1);
        REQUIRE(anchor1->links[0]->next[0]->hash == headers[2].hash());
        REQUIRE(anchor1->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor1->links[0]->next[0]->next[0]->hash == headers[3].hash());
        REQUIRE(anchor1->links[0]->next[0]->next[0]->next.size() == 1);
        REQUIRE(anchor1->links[0]->next[0]->next[0]->next[0]->hash == headers[4].hash());
        REQUIRE(anchor1->links[0]->next[0]->next[0]->next[0]->next.size() == 0);

        REQUIRE(anchor2->links[0]->hash == headers[8].hash());
        REQUIRE(anchor2->links[0]->next.size() == 1);
        REQUIRE(anchor2->links[0]->next[0]->hash == headers[9].hash());
        REQUIRE(anchor2->links[0]->next[0]->next.size() == 0);
    }

    /* chain status:
     *         h1 <----- h2 <----- h3 <----- h4   /   (h7) <----- h8 <----- h9
     *
     * input:
     *         (h5) <----- h6 <----- h7  [h5 not provided]
     *         - triggering extend_down
     *
     * output:
     *         2 anchor, 8 links
     */
    INFO("extend_down") {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[6], headers[7]}, peerId);

        REQUIRE(penalty == Penalty::NoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchors_.size() == 2);
        REQUIRE(chain.anchorQueue_.size() == 3);  // (there is 1 old anchor that will be erased later)
        REQUIRE(chain.linkQueue_.size() == 8);
        REQUIRE(chain.links_.size() == 8);

        // todo: test on link chain
    }

    /* chain status:
     *         h1 <----- h2 <----- h3 <----- h4   /   (h5) <----- h6 <----- h7 <----- h8 <----- h9
     *
     * input:
     *        (h4) <----- h5
     *         - triggering connect
     *
     * output:
     *         1 anchor, 9 links
     */
    INFO("connect") {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[5]}, peerId);

        REQUIRE(penalty == Penalty::NoPenalty);
        REQUIRE(requestMoreHeaders == false);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.anchorQueue_.size() == 3);  // (there are 2 old anchors that will be erased later)
        REQUIRE(chain.linkQueue_.size() == 9);
        REQUIRE(chain.links_.size() == 9);

        // todo: test on link chain
    }
}

// TESTs related to WorkingChain in some tricky cases
// --------------------------------------------------

/* chain:
 *
 *               |-- h2b
 *         h1 <----- h2
 *
 *         1st iteration: receive {h2, h2b} -> new_anchor(h2), new_anchor(h2b) [= 1 anchor with 2 links]
 *         2nd iteration: receive {h1} -> extend_down(h2/h2b) => one anchor(h1) with a link to h1 with 2 link (h2 and h2b)
 */
TEST_CASE("WorkingChain - process_segment - (2) extending down with 2 siblings") {
    using namespace std;

    WorkingChain_ForTest chain;
    chain.top_seen_block_height(1'000'000);

    PeerId peerId = "1";

    std::array<BlockHeader, 10> headers;

    BlockHeader h1;
    h1.number = 1;
    h1.difficulty = 100;

    BlockHeader h2;
    h2.number = 2;
    h2.difficulty = 200;
    h2.parent_hash = h1.hash();

    BlockHeader h2b;
    h2b.number = 2;
    h2b.difficulty = 20;
    h2b.parent_hash = h1.hash();
    h2b.extra_data = string_to_bytes("h2b");  // so hash(h2) != hash(h2b)

    chain.accept_headers({h2, h2b}, peerId);

    chain.accept_headers({h1}, peerId);

    auto anchor = chain.anchors_[h1.parent_hash];
    REQUIRE(anchor != nullptr);
    REQUIRE(anchor->parentHash == h1.parent_hash);
    REQUIRE(anchor->blockHeight == h1.number);

    REQUIRE(anchor->links.size() == 1);
    REQUIRE(anchor->links[0]->has_child(h2.hash()));
    REQUIRE(anchor->links[0]->has_child(h2b.hash()));
}

// TESTs related to WorkingChain::accept_headers (segment manipulation with branches)
// ---------------------------------------------------------------------------------

/* chain:
 *
 *                         |-- h3a<----- h4a             |-- h6a
 *         h1 <----- h2 <----- h3 <----- h4 <----- h5 <----- h6 <----- h7 <----- h8 <----- h9
 *                                                       |-- h6b<----- h7b
 *
 */
TEST_CASE("WorkingChain - process_segment - (3) chain with branches") {
    using namespace std;

    WorkingChain_ForTest chain;
    chain.top_seen_block_height(1'000'000);

    PeerId peerId = "1";

    std::array<BlockHeader, 10> headers;

    for (size_t i = 1; i < headers.size(); i++) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i*100;  // improve!
        headers[i].parent_hash = headers[i - 1].hash();
    }

    BlockHeader h3a;
    h3a.number = 3;
    h3a.difficulty = 1030;
    h3a.parent_hash = headers[2].hash();
    h3a.extra_data = string_to_bytes("h3a");  // so hash(h3a) != hash(h3)

    BlockHeader h4a;
    h4a.number = 4;
    h4a.difficulty = 1040;
    h4a.parent_hash = h3a.hash();
    h4a.extra_data = string_to_bytes("h4a");  // so hash(h4a) != hash(h4)

    BlockHeader h6a;
    h6a.number = 6;
    h6a.difficulty = 1060;
    h6a.parent_hash = headers[5].hash();
    h6a.extra_data = string_to_bytes("h6a");  // so hash(h6a) != hash(h6) != hash(h6b)

    BlockHeader h6b;
    h6b.number = 6;
    h6b.difficulty = 1065;
    h6b.parent_hash = headers[5].hash();
    h6b.extra_data = string_to_bytes("h6b");  // so hash(h6a) != hash(h6) != hash(h6b)

    BlockHeader h7b;
    h7b.number = 7;
    h7b.difficulty = 1070;
    h7b.parent_hash = h6b.hash();
    h7b.extra_data = string_to_bytes("h7b");  // so hash(h7b) != hash(h7)

    /* chain status:
     *         void
     *
     * input:
     *         h1
     *         - triggering new_anchor
     * output:
     *         1 anchor, 1 links -> triggering new_anchor
     */
    INFO("creating first anchor") {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[1]}, peerId);

        REQUIRE(penalty == Penalty::NoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchorQueue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.linkQueue_.size() == 1);
        REQUIRE(chain.links_.size() == 1);

        auto anchor = chain.anchors_[headers[1].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parentHash == headers[1].parent_hash);
        REQUIRE(anchor->blockHeight == headers[1].number);
        REQUIRE(anchor->peerId == peerId);

        REQUIRE(anchor->links.size() == 1);
        REQUIRE(anchor->links[0]->hash == headers[1].hash());
        REQUIRE(anchor->links[0]->next.size() == 0);
    }

    /* chain status:
     *         h1
     *
     * input:
     *                           |-- h3a <----- h4a
     *         (h1) <----- h2 <----- h3
     *
     *         - 3 segments (h3a,h4a), (h3), (h2),  triggering new_anchor, new_anchor, connect
     * output:
     *         1 anchor, 5 links
     */
    INFO("adding 3 segments") {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[2], h3a, h4a, headers[3]}, peerId);

        REQUIRE(penalty == Penalty::NoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchorQueue_.size() == 2);  // there are old anchors
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.linkQueue_.size() == 5);
        REQUIRE(chain.links_.size() == 5);

        auto anchor = chain.anchors_[headers[1].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parentHash == headers[1].parent_hash);
        REQUIRE(anchor->blockHeight == headers[1].number);
        REQUIRE(anchor->peerId == peerId);

        REQUIRE(anchor->links.size() == 1);
        REQUIRE(anchor->links[0]->hash == headers[1].hash());
        REQUIRE(anchor->links[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->hash == headers[2].hash());
        REQUIRE(anchor->links[0]->next[0]->next.size() == 2);
        REQUIRE((anchor->links[0]->next[0]->next[0]->hash == headers[3].hash() ||
                 anchor->links[0]->next[0]->next[0]->hash == h3a.hash()));
        REQUIRE((anchor->links[0]->next[0]->next[1]->hash == headers[3].hash() ||
                 anchor->links[0]->next[0]->next[1]->hash == h3a.hash()));
        REQUIRE((anchor->links[0]->next[0]->next[0]->next[0]->hash == h4a.hash() ||
                 anchor->links[0]->next[0]->next[1]->next[0]->hash == h4a.hash()));
    }

    /* chain status:
     *                           |-- h3a <----- h4a
     *          h1 <------ h2 <----- h3
     *
     * input:
     *                             |-- (h3a) <----- (h4a)
     *         (h1) <----- (h2) <----- (h3)                                      h7 <----- h8 <----- h9
     *
     *         - 1 segment (h7, h8, h9),  triggering new_anchor
     * output:
     *         2 anchor, 8 links
     */
    INFO("adding a disconnected segment") {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[8], headers[9], headers[7]}, peerId);

        REQUIRE(penalty == Penalty::NoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchorQueue_.size() == 3);  // there are old anchors
        REQUIRE(chain.anchors_.size() == 2);
        REQUIRE(chain.linkQueue_.size() == 8);
        REQUIRE(chain.links_.size() == 8);

        auto anchor = chain.anchors_[headers[7].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parentHash == headers[7].parent_hash);
        REQUIRE(anchor->blockHeight == headers[7].number);
        REQUIRE(anchor->peerId == peerId);

        REQUIRE(anchor->links.size() == 1);
        REQUIRE(anchor->links[0]->hash == headers[7].hash());
        REQUIRE(anchor->links[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->hash == headers[8].hash());
        REQUIRE(anchor->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->next[0]->hash == headers[9].hash());
    }

    /* chain status:
     *                           |-- h3a <----- h4a
     *          h1 <------ h2 <----- h3                                           h7 <------ h8 <------- h9
     *
     * input:
     *                             |-- (h3a) <----- (h4a)           |-- h6a
     *         (h1) <----- (h2) <----- (h3)  <----- h4 <----- h5 <----- h6 <----- (h7) <----- (h8) <------ (h9)
     *                                                              |-- h6b<----- h7b
     *         - 4 segment (h7b, h6b)->new_anchor, (h6)->extend_down, (h6a)->new_anchor, (h5, h4)->connect
     * output:
     *         1 anchor, 14 links
     */
    INFO("adding 4 segments connecting chain") {
        auto [penalty, requestMoreHeaders] =
            chain.accept_headers({headers[5], headers[6], h6a, h6b, headers[4], h7b}, peerId);

        REQUIRE(penalty == Penalty::NoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchorQueue_.size() == 4);  // there are old anchors
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.linkQueue_.size() == 14);
        REQUIRE(chain.links_.size() == 14);

        auto link3 = chain.links_[headers[3].hash()];
        REQUIRE(link3 != nullptr);
        REQUIRE(link3->has_child(headers[4].hash()));

        auto link5 = link3->next[0]->next[0];
        REQUIRE(link5->next.size() == 3);
        REQUIRE(link5->has_child(headers[6].hash()));
        REQUIRE(link5->has_child(h6a.hash()));
        REQUIRE(link5->has_child(h6b.hash()));

        auto link6 = chain.links_[headers[6].hash()];
        REQUIRE(link6 != nullptr);
        REQUIRE(link6->next.size() == 1);
        REQUIRE(link6->has_child(headers[7].hash()));

        auto link6b = chain.links_[h6b.hash()];
        REQUIRE(link6b != nullptr);
        REQUIRE(link6b->next.size() == 1);
        REQUIRE(link6b->has_child(h7b.hash()));

        auto anchor = chain.anchors_[headers[1].parent_hash];
        auto curr_link = anchor->links[0];
        for(size_t i = 2; i <= 9; i++) { // verify canonical chain
            auto next_link = curr_link->find_child(headers[i].hash());
            REQUIRE(next_link != curr_link->next.end());
            curr_link = *next_link;
        }
    }
}


// TESTs related to WorkingChain::accept_headers (pre-verified hashes)
// -------------------------------------------------------------------

/* chain:
 *
 *                         |-- h3a<----- h4a             |-- h6a
 *         h1 <----- h2 <----- h3 <----- h4 <----- h5 <----- h6 <----- h7 <----- h8 <----- h9
 *                                                       |-- h6b<----- h7b
 *
 */
TEST_CASE("WorkingChain - process_segment - (4) pre-verified hashes on canonical chain") {
    using namespace std;

    WorkingChain_ForTest chain;
    chain.top_seen_block_height(1'000'000);

    PeerId peerId = "1";

    std::array<BlockHeader, 10> headers;

    for (size_t i = 1; i < headers.size(); i++) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i * 100;  // improve!
        headers[i].parent_hash = headers[i - 1].hash();
    }

    BlockHeader h3a;
    h3a.number = 3;
    h3a.difficulty = 1030;
    h3a.parent_hash = headers[2].hash();
    h3a.extra_data = string_to_bytes("h3a");  // so hash(h3a) != hash(h3)

    BlockHeader h4a;
    h4a.number = 4;
    h4a.difficulty = 1040;
    h4a.parent_hash = h3a.hash();
    h4a.extra_data = string_to_bytes("h4a");  // so hash(h4a) != hash(h4)

    BlockHeader h6a;
    h6a.number = 6;
    h6a.difficulty = 1060;
    h6a.parent_hash = headers[5].hash();
    h6a.extra_data = string_to_bytes("h6a");  // so hash(h6a) != hash(h6) != hash(h6b)

    BlockHeader h6b;
    h6b.number = 6;
    h6b.difficulty = 1065;
    h6b.parent_hash = headers[5].hash();
    h6b.extra_data = string_to_bytes("h6b");  // so hash(h6a) != hash(h6) != hash(h6b)

    BlockHeader h7b;
    h7b.number = 7;
    h7b.difficulty = 1070;
    h7b.parent_hash = h6b.hash();
    h7b.extra_data = string_to_bytes("h7b");  // so hash(h7b) != hash(h7)

    PreverifiedHashes mynet_preverified_hashes = {
        {headers[8].hash(), headers[9].hash()}, // hashes
        headers[9].number                       // height
    };

    chain.set_preverified_hashes(&mynet_preverified_hashes);

    // building the first part of the chain
    chain.accept_headers({headers[1], headers[2], headers[3], h3a, h4a}, peerId);

    // adding the third part fo the chain, disconnected from the first, and that contains a pre-verified hash
    chain.accept_headers({h7b, headers[8], headers[9]}, peerId);

    auto link1 = chain.links_[headers[1].hash()];
    REQUIRE(link1 != nullptr);
    REQUIRE(link1->preverified == false);   // pre-verification can be propagated

    // adding the connecting part of the chain - we expect that pre-verification will be propagated
    chain.accept_headers({headers[4], headers[5], headers[6], h6a, h6b, headers[7]}, peerId);

    // a simple test
    REQUIRE(link1->preverified == true);    // verify propagation

    // canonical chain headers must be pre-verified
    for (size_t i = 1; i < headers.size(); i++) {
        auto link = chain.links_[headers[i].hash()];
        REQUIRE(link != nullptr);
        REQUIRE(link->preverified == true);
    }
    // non canonical headers must be non pre-verified
    for (auto header: {&h3a, &h4a, &h6a, &h6b, &h7b}) {
        auto link = chain.links_[header->hash()];
        REQUIRE(link != nullptr);
        REQUIRE(link->preverified == false);
    }

}

/* chain:
 *
 *                         |-- h3a<----- h4a <---- h5b<----- h6b
 *         h1 <----- h2 <----- h3 <----- h4 <----- h5
 *
 *
 */
TEST_CASE("WorkingChain - process_segment - (5) pre-verified hashes with canonical chain change") {
    using namespace std;

    WorkingChain_ForTest chain;
    chain.top_seen_block_height(1'000'000);

    PeerId peerId = "1";

    std::array<BlockHeader, 6> a_headers;

    for (size_t i = 1; i < a_headers.size(); i++) {  // skip first header for simplicity
        a_headers[i].number = i;
        a_headers[i].difficulty = i * 100;
        a_headers[i].parent_hash = a_headers[i - 1].hash();
    }

    std::array<BlockHeader, 7> b_headers;
    b_headers[2] = a_headers[2];
    for (size_t i = 3; i < b_headers.size(); i++) {  // skip first headers for simplicity
        b_headers[i].number = i;
        b_headers[i].difficulty = i * 100;
        b_headers[i].parent_hash = b_headers[i - 1].hash();
        b_headers[i].extra_data = string_to_bytes("alternate");  // so hash(a_headers[i]) != hash(b_headers[i])
    }

    PreverifiedHashes mynet_preverified_hashes = {
        {b_headers[6].hash()}, // hashes
        b_headers[6].number                   // height
    };

    chain.set_preverified_hashes(&mynet_preverified_hashes);

    // building the first branch of the chain
    chain.accept_headers({a_headers[1], a_headers[2], a_headers[3], a_headers[4], a_headers[5]}, peerId);

    // adding the second branch that becomes canonical
    chain.accept_headers({b_headers[3], b_headers[4], b_headers[5], b_headers[6]}, peerId);

    // verify
    for (size_t i = 1; i < a_headers.size(); i++) {
        auto link = chain.links_[a_headers[i].hash()];
        REQUIRE(link != nullptr);
        if (i == 1 || i == 2)
            REQUIRE(link->preverified == true);
        else
            REQUIRE(link->preverified == false);
    }
    for (size_t i = 3; i < b_headers.size(); i++) {
        auto link = chain.links_[b_headers[i].hash()];
        REQUIRE(link != nullptr);
        REQUIRE(link->preverified == true);
    }

}

}  // namespace silkworm