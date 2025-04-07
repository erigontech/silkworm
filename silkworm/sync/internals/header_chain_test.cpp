// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "header_chain.hpp"

#include <algorithm>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm {
// Useful definitions
// ----------------------------------------------------------------------------

class HeaderChainForTest : public HeaderChain {
  public:  // publication of internal members to test methods functioning
    using HeaderChain::anchor_extension_request;
    using HeaderChain::anchor_queue_;
    using HeaderChain::anchor_skeleton_request;
    using HeaderChain::anchors_;
    using HeaderChain::find_anchor;
    using HeaderChain::generate_request_id;
    using HeaderChain::HeaderChain;
    using HeaderChain::kExtensionReqTimeout;
    using HeaderChain::last_nack_;
    using HeaderChain::links_;
    using HeaderChain::pending_links;
    using HeaderChain::reduce_links_to;

    explicit HeaderChainForTest(const ChainConfig& chain_config)
        : HeaderChain{chain_config, /* use_preverified_hashes = */ false} {}
};

// TESTs related to HeaderList::split_into_segments
// ----------------------------------------------------------------------------

TEST_CASE("HeaderList::split_into_segments no headers") {
    std::vector<BlockHeader> headers;
    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();

    REQUIRE(segments.empty());
    REQUIRE(penalty == Penalty::kNoPenalty);
}

TEST_CASE("HeaderList::split_into_segments single header") {
    std::vector<BlockHeader> headers;
    BlockHeader header;
    header.number = 5;
    headers.push_back(header);

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();

    REQUIRE(segments.size() == 1);
    REQUIRE(penalty == Penalty::kNoPenalty);
}

TEST_CASE("HeaderList::split_into_segments single header repeated twice") {
    std::vector<BlockHeader> headers;
    BlockHeader header;
    header.number = 5;
    headers.push_back(header);
    headers.push_back(header);

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();

    REQUIRE(segments.empty());
    REQUIRE(penalty == Penalty::kDuplicateHeaderPenalty);
}

TEST_CASE("HeaderList::split_into_segments two connected headers") {
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

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();

    REQUIRE(penalty == Penalty::kNoPenalty);
    REQUIRE(segments.size() == 1);                      // 1 segment
    REQUIRE(segments[0].size() == 2);                   // 2 headers
    REQUIRE(segments[0][0]->number == header2.number);  // the max at the beginning
    REQUIRE(segments[0][1]->number == header1.number);
}

TEST_CASE("HeaderList::split_into_segments two connected headers with wrong numbers") {
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

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();

    REQUIRE(segments.empty());
    REQUIRE(penalty == Penalty::kWrongChildBlockHeightPenalty);
}

/* input:
 *         h1 <----- h2
 *               |-- h3
 * output:
 *         3 segments: {h3}, {h2}, {h1}   (in this order)
 */
TEST_CASE("HeaderList::split_into_segments two headers connected to the third header") {
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
        string_view_to_byte_view("I'm different");  // To make sure the hash of h3 is different from the hash of h2
    headers.push_back(header3);

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();

    REQUIRE(penalty == Penalty::kNoPenalty);
    REQUIRE(segments.size() == 3);                      // 3 segment
    REQUIRE(segments[0].size() == 1);                   // 1 headers
    REQUIRE(segments[1].size() == 1);                   // 1 headers
    REQUIRE(segments[2].size() == 1);                   // 1 headers
    REQUIRE(segments[2][0]->number == header1.number);  // expected h1 to be the root
    REQUIRE(segments[1][0]->number == header2.number);
    REQUIRE(segments[0][0]->number == header3.number);
}

TEST_CASE("HeaderList::split_into_segments same three headers, but in a reverse order") {
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
        string_view_to_byte_view("I'm different");  // To make sure the hash of h3 is different from the hash of h2

    headers.push_back(header3);
    headers.push_back(header2);
    headers.push_back(header1);

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();

    REQUIRE(penalty == Penalty::kNoPenalty);
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
TEST_CASE("HeaderList::split_into_segments two headers not connected to each other") {
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
        string_view_to_byte_view("I'm different");  // To make sure the hash of h3 is different from the hash of h2

    headers.push_back(header3);
    headers.push_back(header2);

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();

    REQUIRE(penalty == Penalty::kNoPenalty);
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
TEST_CASE("HeaderList::split_into_segments three headers connected") {
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

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();

    REQUIRE(penalty == Penalty::kNoPenalty);
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
TEST_CASE("HeaderList::split_into_segments four headers connected") {
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
    header4.extra_data = string_view_to_byte_view("I'm different");
    headers.push_back(header4);

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();

    REQUIRE(penalty == Penalty::kNoPenalty);
    REQUIRE(segments.size() == 3);                      // 3 segment
    REQUIRE(segments[0].size() == 1);                   // segment 0 - 1 headers
    REQUIRE(segments[1].size() == 1);                   // segment 1 - 1 headers
    REQUIRE(segments[2].size() == 2);                   // segment 2 - 2 headers
    REQUIRE(segments[2][0]->number == header2.number);  // segments are ordered from high number to
    REQUIRE(segments[2][1]->number == header1.number);
    REQUIRE(segments[0][0] != segments[1][0]);
}

// TESTs related to HeaderChain::accept_headers (segment manipulation: connect, extend_down, extend_up, new_anchor)
// -----------------------------------------------------------------------------------------------------------------

TEST_CASE("HeaderChain: (1) simple chain") {
    using namespace std;
    ChainConfig chain_config{kMainnetConfig};
    chain_config.genesis_hash.emplace(kMainnetGenesisHash);

    HeaderChainForTest chain(chain_config);
    chain.top_seen_block_num(1'000'000);
    auto request_id = chain.generate_request_id();
    PeerId peer_id{byte_ptr_cast("1")};

    std::array<BlockHeader, 10> headers;

    for (size_t i = 1; i < headers.size(); ++i) {  // skip first header for simplicity
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
    INFO("new_anchor");
    {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[1], headers[2]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.pending_links() == 2);
        REQUIRE(chain.links_.size() == 2);

        auto anchor = chain.anchors_[headers[1].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[1].parent_hash);
        REQUIRE(anchor->block_num == headers[1].number);
        REQUIRE(anchor->last_link_block_num == headers[2].number);
        REQUIRE(anchor->peer_id == peer_id);

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
    INFO("extend_up");
    {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[3], headers[4]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == false);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.pending_links() == 4);
        REQUIRE(chain.links_.size() == 4);

        auto anchor = chain.anchors_[headers[1].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[1].parent_hash);
        REQUIRE(anchor->block_num == headers[1].number);
        REQUIRE(anchor->last_link_block_num == headers[4].number);
        REQUIRE(anchor->links.size() == 1);

        REQUIRE(anchor->links[0]->hash == headers[1].hash());
        REQUIRE(anchor->links[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->hash == headers[2].hash());
        REQUIRE(anchor->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->next[0]->hash == headers[3].hash());
        REQUIRE(anchor->links[0]->next[0]->next[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->next[0]->next[0]->hash == headers[4].hash());
        REQUIRE(anchor->links[0]->next[0]->next[0]->next[0]->next.empty());
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
    INFO("new_anchor");
    {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[8], headers[9]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 2);
        REQUIRE(chain.anchors_.size() == 2);
        REQUIRE(chain.pending_links() == 6);
        REQUIRE(chain.links_.size() == 6);

        auto anchor1 = chain.anchors_[headers[1].parent_hash];
        REQUIRE(anchor1 != nullptr);
        REQUIRE(anchor1->parent_hash == headers[1].parent_hash);
        REQUIRE(anchor1->block_num == headers[1].number);
        REQUIRE(anchor1->last_link_block_num == headers[4].number);
        REQUIRE(anchor1->links.size() == 1);

        auto anchor2 = chain.anchors_[headers[8].parent_hash];
        REQUIRE(anchor2 != nullptr);
        REQUIRE(anchor2->parent_hash == headers[8].parent_hash);
        REQUIRE(anchor2->block_num == headers[8].number);
        REQUIRE(anchor2->last_link_block_num == headers[9].number);
        REQUIRE(anchor2->links.size() == 1);

        REQUIRE(anchor1->links[0]->hash == headers[1].hash());
        REQUIRE(anchor1->links[0]->next.size() == 1);
        REQUIRE(anchor1->links[0]->next[0]->hash == headers[2].hash());
        REQUIRE(anchor1->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor1->links[0]->next[0]->next[0]->hash == headers[3].hash());
        REQUIRE(anchor1->links[0]->next[0]->next[0]->next.size() == 1);
        REQUIRE(anchor1->links[0]->next[0]->next[0]->next[0]->hash == headers[4].hash());
        REQUIRE(anchor1->links[0]->next[0]->next[0]->next[0]->next.empty());

        REQUIRE(anchor2->links[0]->hash == headers[8].hash());
        REQUIRE(anchor2->links[0]->next.size() == 1);
        REQUIRE(anchor2->links[0]->next[0]->hash == headers[9].hash());
        REQUIRE(anchor2->links[0]->next[0]->next.empty());
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
    INFO("extend_down");
    {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[6], headers[7]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchors_.size() == 2);
        REQUIRE(chain.anchor_queue_.size() == 2);
        REQUIRE(chain.pending_links() == 8);
        REQUIRE(chain.links_.size() == 8);

        auto anchor1 = chain.anchors_[headers[1].parent_hash];
        REQUIRE(anchor1 != nullptr);
        REQUIRE(anchor1->parent_hash == headers[1].parent_hash);
        REQUIRE(anchor1->block_num == headers[1].number);
        REQUIRE(anchor1->last_link_block_num == headers[4].number);
        REQUIRE(anchor1->links.size() == 1);

        auto anchor2 = chain.anchors_[headers[6].parent_hash];
        REQUIRE(anchor2 != nullptr);
        REQUIRE(anchor2->parent_hash == headers[6].parent_hash);
        REQUIRE(anchor2->block_num == headers[6].number);
        REQUIRE(anchor2->last_link_block_num == headers[9].number);
        REQUIRE(anchor2->links.size() == 1);

        REQUIRE(anchor2->links[0]->hash == headers[6].hash());
        REQUIRE(anchor2->links[0]->next.size() == 1);
        REQUIRE(anchor2->links[0]->next[0]->hash == headers[7].hash());
        REQUIRE(anchor2->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor2->links[0]->next[0]->next[0]->hash == headers[8].hash());
        REQUIRE(anchor2->links[0]->next[0]->next[0]->next.size() == 1);
        REQUIRE(anchor2->links[0]->next[0]->next[0]->next[0]->hash == headers[9].hash());
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
    INFO("connect");
    {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[5]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == false);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.pending_links() == 9);
        REQUIRE(chain.links_.size() == 9);

        auto anchor = chain.anchors_[headers[1].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[1].parent_hash);
        REQUIRE(anchor->block_num == headers[1].number);
        REQUIRE(anchor->last_link_block_num == headers[9].number);
        REQUIRE(anchor->links.size() == 1);

        size_t i = 1;
        auto* current_links = &(anchor->links);
        while (!current_links->empty()) {
            REQUIRE(current_links->at(0)->hash == headers[i].hash());
            current_links = &(current_links->at(0)->next);
            ++i;
        }
        REQUIRE(i == 10);
    }
}

// TESTs related to HeaderChain in some tricky cases
// --------------------------------------------------

/* chain:
 *
 *               |-- h2b
 *         h1 <----- h2
 *
 *         1st iteration: receive {h2, h2b} -> new_anchor(h2), new_anchor(h2b) [= 1 anchor with 2 links]
 *         2nd iteration: receive {h1} -> extend_down(h2/h2b) => one anchor(h1) with a link to h1 with 2 links
 *                                                                                                (h2 and h2b)
 */
TEST_CASE("HeaderChain: (2) extending down with 2 siblings") {
    using namespace std;

    ChainConfig chain_config{kMainnetConfig};
    chain_config.genesis_hash.emplace(kMainnetGenesisHash);

    HeaderChainForTest chain(chain_config);
    chain.top_seen_block_num(1'000'000);
    auto request_id = chain.generate_request_id();
    PeerId peer_id{byte_ptr_cast("1")};

    std::array<BlockHeader, 10> headers;

    BlockHeader h0;
    h0.number = 0;
    h0.difficulty = 0;

    BlockHeader h1;
    h1.number = 1;
    h1.difficulty = 100;
    h1.parent_hash = h0.hash();

    BlockHeader h2;
    h2.number = 2;
    h2.difficulty = 200;
    h2.parent_hash = h1.hash();

    BlockHeader h2b;
    h2b.number = 2;
    h2b.difficulty = 20;
    h2b.parent_hash = h1.hash();
    h2b.extra_data = string_view_to_byte_view("h2b");  // so hash(h2) != hash(h2b)

    chain.accept_headers({h2, h2b}, request_id, peer_id);

    chain.accept_headers({h1}, request_id, peer_id);

    REQUIRE(chain.anchors_.size() == 1);

    auto anchor = chain.anchors_[h1.parent_hash];
    REQUIRE(anchor != nullptr);
    REQUIRE(anchor->parent_hash == h1.parent_hash);
    REQUIRE(anchor->block_num == h1.number);

    REQUIRE(anchor->links.size() == 1);
    REQUIRE(anchor->links[0]->has_child(h2.hash()));
    REQUIRE(anchor->links[0]->has_child(h2b.hash()));
}

// TESTs related to HeaderChain::accept_headers (segment manipulation with branches)
// ---------------------------------------------------------------------------------

/* chain:
 *
 *                         |-- h3a<----- h4a             |-- h6a
 *         h1 <----- h2 <----- h3 <----- h4 <----- h5 <----- h6 <----- h7 <----- h8 <----- h9
 *                                                       |-- h6b<----- h7b
 *
 */
TEST_CASE("HeaderChain: (3) chain with branches") {
    using namespace std;

    ChainConfig chain_config{kMainnetConfig};
    chain_config.genesis_hash.emplace(kMainnetGenesisHash);

    HeaderChainForTest chain(chain_config);
    chain.top_seen_block_num(1'000'000);
    auto request_id = chain.generate_request_id();
    PeerId peer_id{byte_ptr_cast("1")};

    std::array<BlockHeader, 10> headers;

    for (size_t i = 1; i < headers.size(); ++i) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i * 100;  // improve!
        headers[i].parent_hash = headers[i - 1].hash();
    }

    BlockHeader h3a;
    h3a.number = 3;
    h3a.difficulty = 1030;
    h3a.parent_hash = headers[2].hash();
    h3a.extra_data = string_view_to_byte_view("h3a");  // so hash(h3a) != hash(h3)

    BlockHeader h4a;
    h4a.number = 4;
    h4a.difficulty = 1040;
    h4a.parent_hash = h3a.hash();
    h4a.extra_data = string_view_to_byte_view("h4a");  // so hash(h4a) != hash(h4)

    BlockHeader h6a;
    h6a.number = 6;
    h6a.difficulty = 1060;
    h6a.parent_hash = headers[5].hash();
    h6a.extra_data = string_view_to_byte_view("h6a");  // so hash(h6a) != hash(h6) != hash(h6b)

    BlockHeader h6b;
    h6b.number = 6;
    h6b.difficulty = 1065;
    h6b.parent_hash = headers[5].hash();
    h6b.extra_data = string_view_to_byte_view("h6b");  // so hash(h6a) != hash(h6) != hash(h6b)

    BlockHeader h7b;
    h7b.number = 7;
    h7b.difficulty = 1070;
    h7b.parent_hash = h6b.hash();
    h7b.extra_data = string_view_to_byte_view("h7b");  // so hash(h7b) != hash(h7)

    /* chain status:
     *         void
     *
     * input:
     *         h1
     *         - triggering new_anchor
     * output:
     *         1 anchor, 1 links -> triggering new_anchor
     */
    INFO("creating first anchor");
    {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[1]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.links_.size() == 1);

        auto anchor = chain.anchors_[headers[1].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[1].parent_hash);
        REQUIRE(anchor->block_num == headers[1].number);
        REQUIRE(anchor->peer_id == peer_id);

        REQUIRE(anchor->links.size() == 1);
        REQUIRE(anchor->links[0]->hash == headers[1].hash());
        REQUIRE(anchor->links[0]->next.empty());
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
    INFO("adding 3 segments");
    {
        auto [penalty, requestMoreHeaders] =
            chain.accept_headers({headers[2], h3a, h4a, headers[3]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.links_.size() == 5);

        auto anchor = chain.anchors_[headers[1].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[1].parent_hash);
        REQUIRE(anchor->block_num == headers[1].number);
        REQUIRE(anchor->peer_id == peer_id);

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
    INFO("adding a disconnected segment");
    {
        auto [penalty, requestMoreHeaders] =
            chain.accept_headers({headers[8], headers[9], headers[7]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 2);
        REQUIRE(chain.anchors_.size() == 2);
        REQUIRE(chain.links_.size() == 8);

        auto anchor = chain.anchors_[headers[7].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[7].parent_hash);
        REQUIRE(anchor->block_num == headers[7].number);
        REQUIRE(anchor->peer_id == peer_id);

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
    SECTION("adding 4 segments connecting chain") {
        auto [penalty, requestMoreHeaders] =
            chain.accept_headers({headers[5], headers[6], h6a, h6b, headers[4], h7b}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
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
        for (size_t i = 2; i <= 9; ++i) {  // verify canonical chain
            auto next_link = curr_link->find_child(headers[i].hash());
            REQUIRE(next_link != curr_link->next.end());
            curr_link = *next_link;
        }
    }
}

// TESTs related to HeaderChain::accept_headers (pre-verified hashes)
// -------------------------------------------------------------------

/* chain:
 *
 *                         |-- h3a<----- h4a             |-- h6a
 *         h1 <----- h2 <----- h3 <----- h4 <----- h5 <----- h6 <----- h7 <----- h8 <----- h9
 *                                                       |-- h6b<----- h7b
 *
 */
TEST_CASE("HeaderChain: (4) pre-verified hashes on canonical chain") {
    using namespace std;

    ChainConfig chain_config{kMainnetConfig};
    chain_config.genesis_hash.emplace(kMainnetGenesisHash);

    HeaderChainForTest chain(chain_config);
    chain.top_seen_block_num(1'000'000);
    auto request_id = chain.generate_request_id();
    PeerId peer_id{byte_ptr_cast("1")};

    std::array<BlockHeader, 10> headers;

    for (size_t i = 1; i < headers.size(); ++i) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i * 100;  // improve!
        headers[i].parent_hash = headers[i - 1].hash();
    }

    BlockHeader h3a;
    h3a.number = 3;
    h3a.difficulty = 1030;
    h3a.parent_hash = headers[2].hash();
    h3a.extra_data = string_view_to_byte_view("h3a");  // so hash(h3a) != hash(h3)

    BlockHeader h4a;
    h4a.number = 4;
    h4a.difficulty = 1040;
    h4a.parent_hash = h3a.hash();
    h4a.extra_data = string_view_to_byte_view("h4a");  // so hash(h4a) != hash(h4)

    BlockHeader h6a;
    h6a.number = 6;
    h6a.difficulty = 1060;
    h6a.parent_hash = headers[5].hash();
    h6a.extra_data = string_view_to_byte_view("h6a");  // so hash(h6a) != hash(h6) != hash(h6b)

    BlockHeader h6b;
    h6b.number = 6;
    h6b.difficulty = 1065;
    h6b.parent_hash = headers[5].hash();
    h6b.extra_data = string_view_to_byte_view("h6b");  // so hash(h6a) != hash(h6) != hash(h6b)

    BlockHeader h7b;
    h7b.number = 7;
    h7b.difficulty = 1070;
    h7b.parent_hash = h6b.hash();
    h7b.extra_data = string_view_to_byte_view("h7b");  // so hash(h7b) != hash(h7)

    PreverifiedHashes mynet_preverified_hashes = {
        {headers[8].hash(), headers[9].hash()},  // hashes
        headers[9].number                        // block_num
    };

    chain.set_preverified_hashes(mynet_preverified_hashes);

    // building the first part of the chain
    chain.accept_headers({headers[1], headers[2], headers[3], h3a, h4a}, request_id, peer_id);

    // adding the third part fo the chain, disconnected from the first, and that contains a pre-verified hash
    chain.accept_headers({h7b, headers[8], headers[9]}, request_id, peer_id);

    auto link1 = chain.links_[headers[1].hash()];
    REQUIRE(link1 != nullptr);
    REQUIRE(link1->preverified == false);  // pre-verification can be propagated

    // adding the connecting part of the chain - we expect that pre-verification will be propagated
    chain.accept_headers({headers[4], headers[5], headers[6], h6a, h6b, headers[7]}, request_id, peer_id);

    // a simple test
    REQUIRE(link1->preverified == true);  // verify propagation

    // canonical chain headers must be pre-verified
    for (size_t i = 1; i < headers.size(); ++i) {
        auto link = chain.links_[headers[i].hash()];
        REQUIRE(link != nullptr);
        REQUIRE(link->preverified == true);
    }
    // non-canonical headers must be non pre-verified
    for (auto header : {&h3a, &h4a, &h6a, &h6b, &h7b}) {
        auto link = chain.links_[header->hash()];
        REQUIRE(link != nullptr);
        REQUIRE(link->preverified == false);
    }
}

/* chain:
 *
 *       h1 <----- h2 <----- h3 <----- h4 <----- h5 <----- h6 (pre-verified)
 *
 */
TEST_CASE("HeaderChain: (5) pre-verified hashes") {
    using namespace std;

    ChainConfig chain_config{kMainnetConfig};
    chain_config.genesis_hash.emplace(kMainnetGenesisHash);

    HeaderChainForTest chain(chain_config);
    chain.top_seen_block_num(1'000'000);
    auto request_id = chain.generate_request_id();
    PeerId peer_id{byte_ptr_cast("1")};

    std::array<BlockHeader, 7> headers;

    for (size_t i = 1; i < headers.size(); ++i) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i * 100;
        headers[i].parent_hash = headers[i - 1].hash();
    }

    PreverifiedHashes mynet_preverified_hashes = {
        {headers[6].hash()},  // hashes
        headers[6].number     // block_num
    };

    chain.set_preverified_hashes(mynet_preverified_hashes);

    // building the first chain segment
    chain.accept_headers({headers[1]}, request_id, peer_id);

    /*
     *    h1 <-----                                  <----- h6 (pre-verified)
     */
    INFO("new anchor");
    {
        // adding the last chain segment
        chain.accept_headers({headers[6]}, request_id, peer_id);

        auto link = chain.links_[headers[6].hash()];
        REQUIRE(link->preverified == true);
    }

    /*
     *    h1 <-----              <----- h4 <----- h5 <----- h6 (pre-verified)
     */
    INFO("extend down");
    {
        // adding two headers to extend down the anchor
        chain.accept_headers({headers[5], headers[4]}, request_id, peer_id);

        // check pre-verification propagation
        auto link5 = chain.links_[headers[5].hash()];
        REQUIRE(link5->preverified == true);
        auto link4 = chain.links_[headers[4].hash()];
        REQUIRE(link4->preverified == true);
    }

    /*
     *    h1 <----- h2 <----- h3 <----- h4 <----- h5 <----- h6 (pre-verified)
     */
    INFO("connect");
    {
        // adding two headers to extend down the anchor
        chain.accept_headers({headers[2], headers[3]}, request_id, peer_id);

        // check pre-verification propagation
        auto link1 = chain.links_[headers[1].hash()];
        REQUIRE(link1->preverified == true);
        auto link2 = chain.links_[headers[2].hash()];
        REQUIRE(link2->preverified == true);
        auto link3 = chain.links_[headers[3].hash()];
        REQUIRE(link3->preverified == true);
    }
}

/* chain:
 *
 *                         |-- h3a<----- h4a <---- h5b<----- h6b
 *         h1 <----- h2 <----- h3 <----- h4 <----- h5
 *
 *
 */
TEST_CASE("HeaderChain: (5') pre-verified hashes with canonical chain change") {
    using namespace std;

    ChainConfig chain_config{kMainnetConfig};
    chain_config.genesis_hash.emplace(kMainnetGenesisHash);

    HeaderChainForTest chain(chain_config);
    chain.top_seen_block_num(1'000'000);
    auto request_id = chain.generate_request_id();
    PeerId peer_id{byte_ptr_cast("1")};

    std::array<BlockHeader, 6> a_headers;

    for (size_t i = 1; i < a_headers.size(); ++i) {  // skip first header for simplicity
        a_headers[i].number = i;
        a_headers[i].difficulty = i * 100;
        a_headers[i].parent_hash = a_headers[i - 1].hash();
    }

    std::array<BlockHeader, 7> b_headers;
    b_headers[2] = a_headers[2];
    for (size_t i = 3; i < b_headers.size(); ++i) {  // skip first headers for simplicity
        b_headers[i].number = i;
        b_headers[i].difficulty = i * 100;
        b_headers[i].parent_hash = b_headers[i - 1].hash();
        b_headers[i].extra_data = string_view_to_byte_view("alternate");  // so hash(a_headers[i]) != hash(b_headers[i])
    }

    PreverifiedHashes mynet_preverified_hashes = {
        {b_headers[6].hash()},  // hashes
        b_headers[6].number     // block_num
    };

    chain.set_preverified_hashes(mynet_preverified_hashes);

    // building the first branch of the chain
    chain.accept_headers({a_headers[1], a_headers[2], a_headers[3], a_headers[4], a_headers[5]}, request_id, peer_id);

    // adding the second branch that becomes canonical
    chain.accept_headers({b_headers[3], b_headers[4], b_headers[5], b_headers[6]}, request_id, peer_id);

    // verify
    for (size_t i = 1; i < a_headers.size(); ++i) {
        auto link = chain.links_[a_headers[i].hash()];
        REQUIRE(link != nullptr);
        if (i == 1 || i == 2)
            REQUIRE(link->preverified == true);
        else
            REQUIRE(link->preverified == false);
    }
    for (size_t i = 3; i < b_headers.size(); ++i) {
        auto link = chain.links_[b_headers[i].hash()];
        REQUIRE(link != nullptr);
        REQUIRE(link->preverified == true);
    }
}

// Corner cases
// -----------------------------------------------------------------------------------------------------------------

TEST_CASE("HeaderChain: (6) (malicious) siblings") {
    using namespace std;

    ChainConfig chain_config{kMainnetConfig};
    chain_config.genesis_hash.emplace(kMainnetGenesisHash);

    HeaderChainForTest chain(chain_config);
    chain.top_seen_block_num(1'000'000);
    auto request_id = chain.generate_request_id();
    PeerId peer_id{byte_ptr_cast("1")};

    std::array<BlockHeader, 10> headers;

    headers[0].number = 0;
    headers[0].difficulty = 0;
    for (size_t i = 1; i < headers.size(); ++i) {
        headers[i].number = i;
        headers[i].difficulty = i;  // improve!
        headers[i].parent_hash = headers[i - 1].hash();
    }

    /* chain:
     *         h5
     */
    INFO("new_anchor");
    {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({headers[5]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.links_.size() == 1);

        auto anchor = chain.anchors_[headers[5].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[5].parent_hash);
        REQUIRE(anchor->block_num == headers[5].number);
        REQUIRE(anchor->peer_id == peer_id);

        REQUIRE(anchor->links.size() == 1);
        REQUIRE(anchor->links[0]->hash == headers[5].hash());
        REQUIRE(anchor->links[0]->next.empty());
    }

    /* chain:
     *         h3 <-- h4 <-- h5
     */
    INFO("extend_down overlapping");
    {
        auto [penalty, requestMoreHeaders] = chain.accept_headers(
            {headers[5], headers[4], headers[3]}, request_id, peer_id);  // add a segment that overlap the previous one

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.links_.size() == 3);

        auto anchor = chain.anchors_[headers[3].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[3].parent_hash);
        REQUIRE(anchor->block_num == headers[3].number);
        REQUIRE(anchor->links.size() == 1);

        REQUIRE(anchor->links[0]->hash == headers[3].hash());
        REQUIRE(anchor->links[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->hash == headers[4].hash());
        REQUIRE(anchor->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->next[0]->hash == headers[5].hash());
        REQUIRE(anchor->links[0]->next[0]->next[0]->next.empty());
    }

    /* chain:
     *     (h2) <--- h3 <--- h4 <--- h5
     *      |----------------------- h5'
     */
    INFO("extend up with wrong header");
    {
        BlockHeader h5p;
        h5p.number = 5;
        h5p.parent_hash = headers[2].hash();  // wrong, it should have number = 3
        h5p.difficulty = headers[2].difficulty + 1;

        // add a segment with a siblings with far parent
        auto [penalty, requestMoreHeaders] = chain.accept_headers({h5p}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == false);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.links_.size() == 4);

        auto anchor = chain.anchors_[headers[3].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[3].parent_hash);
        REQUIRE(anchor->block_num == headers[3].number);
        REQUIRE(anchor->links.size() == 2);  // 2 siblings

        REQUIRE(anchor->links[0]->hash == headers[3].hash());
        REQUIRE(anchor->links[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->hash == headers[4].hash());
        REQUIRE(anchor->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->next[0]->hash == headers[5].hash());
        REQUIRE(anchor->links[0]->next[0]->next[0]->next.empty());

        REQUIRE(anchor->links[1]->hash == h5p.hash());
    }

    /* chain:
     *     (h2) <--- h3 <--- h4 <--- h5
     *      |----------------------- h5'
     *                         X---- h5"
     */
    INFO("new anchor with unknown parent");
    {
        BlockHeader h5s;
        h5s.number = 5;
        h5s.parent_hash = h5s.hash();  // a wrong hash
        h5s.difficulty = 5;

        // add a segment with a siblings with far parent
        auto [penalty, requestMoreHeaders] = chain.accept_headers({h5s}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 2);
        REQUIRE(chain.anchors_.size() == 2);
        REQUIRE(chain.links_.size() == 5);

        auto anchor = chain.anchors_[headers[3].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[3].parent_hash);
        REQUIRE(anchor->block_num == headers[3].number);
        REQUIRE(anchor->links.size() == 2);  // 2 siblings

        auto anchor2 = chain.anchors_[h5s.parent_hash];
        REQUIRE(anchor2 != nullptr);
        REQUIRE(anchor2->links[0]->hash == h5s.hash());
    }
}

TEST_CASE("HeaderChain: (7) invalidating anchor") {
    using namespace std;

    ChainConfig chain_config{kMainnetConfig};
    chain_config.genesis_hash.emplace(kMainnetGenesisHash);

    HeaderChainForTest chain(chain_config);
    chain.top_seen_block_num(1'000'000);
    auto request_id = chain.generate_request_id();
    PeerId peer_id{byte_ptr_cast("1")};

    std::array<BlockHeader, 10> headers;

    for (size_t i = 1; i < headers.size(); ++i) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i;  // improve!
        headers[i].parent_hash = headers[i - 1].hash();
    }

    BlockHeader h5p;
    h5p.number = 5;
    h5p.difficulty = 5;
    h5p.extra_data = string_view_to_byte_view("I'm different");
    h5p.parent_hash = headers[4].hash();
    INFO("new_anchor");
    {
        auto [penalty, requestMoreHeaders] =
            chain.accept_headers({headers[5], h5p, headers[6], headers[7]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.links_.size() == 4);

        auto anchor = chain.anchors_[headers[5].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[5].parent_hash);
        REQUIRE(anchor->block_num == headers[5].number);
        REQUIRE(anchor->peer_id == peer_id);

        REQUIRE(anchor->links.size() == 2);
        REQUIRE(anchor->has_child(headers[5].hash()));
        REQUIRE(anchor->has_child(h5p.hash()));
        auto child1 = *(anchor->find_child(headers[5].hash()));
        REQUIRE(child1->next[0]->hash == headers[6].hash());
    }

    INFO("invalidating");
    {
        using namespace std::literals::chrono_literals;

        time_point_t now = std::chrono::system_clock::now();
        seconds_t timeout = HeaderChainForTest::kExtensionReqTimeout;

        auto anchor = chain.anchor_queue_.top();
        anchor->timeouts = 10;
        anchor->timestamp = now - timeout;

        std::shared_ptr<OutboundMessage> message = chain.anchor_extension_request(now);
        REQUIRE(message != nullptr);

        auto get_headers_msg = std::dynamic_pointer_cast<OutboundGetBlockHeaders>(message);
        REQUIRE(get_headers_msg != nullptr);

        CHECK(!get_headers_msg->packet_present());
        auto penalizations = get_headers_msg->penalties();
        CHECK(!penalizations.empty());

        CHECK(chain.anchor_queue_.empty());
        CHECK(chain.anchors_.empty());
        CHECK(chain.links_.empty());
    }

    INFO("new_anchor again");
    {
        auto [penalty, requestMoreHeaders] = chain.accept_headers(
            {headers[5], headers[4], headers[3]}, request_id, peer_id);  // add a segment that overlap the previous one

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.links_.size() == 3);

        auto anchor = chain.anchors_[headers[3].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[3].parent_hash);
        REQUIRE(anchor->block_num == headers[3].number);
        REQUIRE(anchor->links.size() == 1);

        REQUIRE(anchor->links[0]->hash == headers[3].hash());
        REQUIRE(anchor->links[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->hash == headers[4].hash());
        REQUIRE(anchor->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->next[0]->hash == headers[5].hash());
        REQUIRE(anchor->links[0]->next[0]->next[0]->next.empty());
    }
}

TEST_CASE("HeaderChain: (8) sibling with anchor invalidation and links reduction") {
    using namespace std;

    ChainConfig chain_config{kMainnetConfig};
    chain_config.genesis_hash.emplace(kMainnetGenesisHash);

    HeaderChainForTest chain(chain_config);
    chain.top_seen_block_num(1'000'000);
    auto request_id = chain.generate_request_id();
    PeerId peer_id{byte_ptr_cast("1")};

    std::array<BlockHeader, 10> headers;

    for (size_t i = 1; i < headers.size(); ++i) {  // skip first header for simplicity
        headers[i].number = i;
        headers[i].difficulty = i;  // improve!
        headers[i].parent_hash = headers[i - 1].hash();
    }

    BlockHeader h5p;
    h5p.number = 5;
    h5p.difficulty = 5;
    h5p.parent_hash = h5p.hash();  // a wrong hash, h5p hash will also be different

    INFO("a wrong anchor");
    {
        auto [penalty, requestMoreHeaders] = chain.accept_headers({h5p}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.links_.size() == 1);

        auto anchor = chain.anchors_[h5p.parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == h5p.parent_hash);
        REQUIRE(anchor->block_num == h5p.number);
        REQUIRE(anchor->last_link_block_num == h5p.number);
        REQUIRE(anchor->peer_id == peer_id);

        REQUIRE(anchor->links.size() == 1);
        REQUIRE(anchor->links[0]->hash == h5p.hash());
        REQUIRE(anchor->links[0]->next.empty());
    }

    INFO("a segment with a sibling");
    {
        // ad a segment terminating with the header[5] that is a sibling of the anchor h5p
        auto [penalty, requestMoreHeaders] =
            chain.accept_headers({headers[3], headers[4], headers[5]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == true);
        REQUIRE(chain.anchor_queue_.size() == 2);
        REQUIRE(chain.anchors_.size() == 2);
        REQUIRE(chain.links_.size() == 4);

        auto anchor1 = chain.anchors_[h5p.parent_hash];
        REQUIRE(anchor1 != nullptr);
        REQUIRE(anchor1->parent_hash == h5p.parent_hash);
        REQUIRE(anchor1->block_num == h5p.number);
        REQUIRE(anchor1->last_link_block_num == h5p.number);
        REQUIRE(anchor1->peer_id == peer_id);

        REQUIRE(anchor1->links.size() == 1);
        REQUIRE(anchor1->links[0]->hash == h5p.hash());
        REQUIRE(anchor1->links[0]->next.empty());

        auto link5b = chain.links_[h5p.hash()];
        REQUIRE(link5b != nullptr);
        REQUIRE(link5b->block_num == 5);
        REQUIRE(link5b->hash == h5p.hash());

        auto anchor2 = chain.anchors_[headers[3].parent_hash];
        REQUIRE(anchor2 != nullptr);
        REQUIRE(anchor2->parent_hash == headers[3].parent_hash);
        REQUIRE(anchor2->block_num == headers[3].number);
        REQUIRE(anchor2->last_link_block_num == headers[5].number);
        REQUIRE(anchor2->peer_id == peer_id);

        REQUIRE(anchor2->links[0]->hash == headers[3].hash());
        REQUIRE(anchor2->links[0]->next.size() == 1);
        REQUIRE(anchor2->links[0]->next[0]->hash == headers[4].hash());
        REQUIRE(anchor2->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor2->links[0]->next[0]->next[0]->hash == headers[5].hash());
        REQUIRE(anchor2->links[0]->next[0]->next[0]->next.empty());
    }

    INFO("failed extending anchor");
    {
        // trying extending h5p get the correct chain, headers[3], headers[4], headers[5], so extending fails
        auto [penalty, requestMoreHeaders] =
            chain.accept_headers({headers[3], headers[4], headers[5]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == false);  // fails to extend

        // following conditions are as before

        REQUIRE(chain.anchor_queue_.size() == 2);
        REQUIRE(chain.anchors_.size() == 2);
        REQUIRE(chain.links_.size() == 4);

        auto anchor1 = chain.anchors_[h5p.parent_hash];
        REQUIRE(anchor1 != nullptr);
        REQUIRE(anchor1->parent_hash == h5p.parent_hash);
        REQUIRE(anchor1->block_num == h5p.number);
        REQUIRE(anchor1->last_link_block_num == h5p.number);
        REQUIRE(anchor1->peer_id == peer_id);

        REQUIRE(anchor1->links.size() == 1);
        REQUIRE(anchor1->links[0]->hash == h5p.hash());
        REQUIRE(anchor1->links[0]->next.empty());

        auto link5b = chain.links_[h5p.hash()];
        REQUIRE(link5b != nullptr);
        REQUIRE(link5b->block_num == 5);
        REQUIRE(link5b->hash == h5p.hash());

        auto anchor2 = chain.anchors_[headers[3].parent_hash];
        REQUIRE(anchor2 != nullptr);
        REQUIRE(anchor2->parent_hash == headers[3].parent_hash);
        REQUIRE(anchor2->block_num == headers[3].number);
        REQUIRE(anchor2->last_link_block_num == headers[5].number);
        REQUIRE(anchor2->peer_id == peer_id);

        REQUIRE(anchor2->links[0]->hash == headers[3].hash());
        REQUIRE(anchor2->links[0]->next.size() == 1);
        REQUIRE(anchor2->links[0]->next[0]->hash == headers[4].hash());
        REQUIRE(anchor2->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor2->links[0]->next[0]->next[0]->hash == headers[5].hash());
        REQUIRE(anchor2->links[0]->next[0]->next[0]->next.empty());
    }

    INFO("requesting again an anchor");
    {
        using namespace std::literals::chrono_literals;

        // affected anchor
        std::shared_ptr<Anchor> anchor = chain.anchor_queue_.top();
        auto prev_timeouts = anchor->timeouts;
        auto prev_timestamp = anchor->timestamp;
        auto timeout = HeaderChainForTest::kExtensionReqTimeout;
        auto now = prev_timestamp + timeout;

        // request an anchor extension
        std::shared_ptr<OutboundMessage> message = chain.anchor_extension_request(now);
        REQUIRE(message != nullptr);

        auto get_headers_msg = std::dynamic_pointer_cast<OutboundGetBlockHeaders>(message);
        REQUIRE(get_headers_msg != nullptr);

        // checks
        CHECK(get_headers_msg->packet_present());
        auto packet = get_headers_msg->packet();

        auto penalizations = get_headers_msg->penalties();
        CHECK(penalizations.empty());

        CHECK(anchor->timeouts == prev_timeouts + 1);
        CHECK(anchor->timestamp > now);

        CHECK(chain.anchor_queue_.size() == 2);
        CHECK(chain.anchors_.size() == 2);
        CHECK(chain.links_.size() == 4);

        // undo the request
        chain.request_nack(packet);

        CHECK(anchor->timeouts == prev_timeouts);
        CHECK(anchor->timestamp == prev_timestamp);
    }

    INFO("invalidating");
    {
        using namespace std::literals::chrono_literals;

        time_point_t now = std::chrono::system_clock::now();
        seconds_t timeout = HeaderChainForTest::kExtensionReqTimeout;

        chain.last_nack_ = now - timeout;  // otherwise the request is ignored

        auto anchor1 = chain.anchors_[h5p.parent_hash];
        chain.anchor_queue_.update(anchor1, [&](auto& a) {
            a->timeouts = 10;  // this cause invalidation
            a->timestamp = now - timeout;
        });

        auto anchor2 = chain.anchors_[headers[3].parent_hash];
        chain.anchor_queue_.update(anchor2, [&](auto& a) {
            a->timestamp = now + timeout;  // avoid extension now
        });

        std::shared_ptr<OutboundMessage> message = chain.anchor_extension_request(now);
        REQUIRE(message != nullptr);

        auto get_headers_msg = std::dynamic_pointer_cast<OutboundGetBlockHeaders>(message);
        REQUIRE(get_headers_msg != nullptr);

        CHECK(!get_headers_msg->packet_present());
        CHECK(!get_headers_msg->penalties().empty());

        REQUIRE(chain.anchor_queue_.size() == 1);  // one less
        REQUIRE(chain.anchors_.size() == 1);       // one less
        REQUIRE(chain.links_.size() == 3);         // one less

        auto anchor1b_it = chain.anchors_.find(h5p.parent_hash);
        REQUIRE(anchor1b_it == chain.anchors_.end());

        auto link5b_it = chain.links_.find(h5p.hash());
        REQUIRE(link5b_it == chain.links_.end());

        // following conditions are as before

        anchor2 = chain.anchors_[headers[3].parent_hash];
        REQUIRE(anchor2 != nullptr);
        REQUIRE(anchor2->parent_hash == headers[3].parent_hash);
        REQUIRE(anchor2->block_num == headers[3].number);
        REQUIRE(anchor2->last_link_block_num == headers[5].number);
        REQUIRE(anchor2->peer_id == peer_id);

        REQUIRE(anchor2->links[0]->hash == headers[3].hash());
        REQUIRE(anchor2->links[0]->next.size() == 1);
        REQUIRE(anchor2->links[0]->next[0]->hash == headers[4].hash());
        REQUIRE(anchor2->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor2->links[0]->next[0]->next[0]->hash == headers[5].hash());
        REQUIRE(anchor2->links[0]->next[0]->next[0]->next.empty());
    }

    INFO("reducing links");
    {
        // add a new anchor + link
        chain.accept_headers({headers[7], headers[8]}, request_id, peer_id);

        chain.reduce_links_to(3);

        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.links_.size() == 3);

        auto anchor = chain.anchors_[headers[3].parent_hash];
        REQUIRE(anchor != nullptr);
        REQUIRE(anchor->parent_hash == headers[3].parent_hash);
        REQUIRE(anchor->block_num == headers[3].number);
        REQUIRE(anchor->last_link_block_num == headers[5].number);  // this is wrong, change the code of reduce_links_to()
        REQUIRE(anchor->links.size() == 1);

        auto link7_it = chain.links_.find(headers[7].hash());
        REQUIRE(link7_it == chain.links_.end());
        auto link8_it = chain.links_.find(headers[8].hash());
        REQUIRE(link8_it == chain.links_.end());

        REQUIRE(anchor->links[0]->hash == headers[3].hash());
        REQUIRE(anchor->links[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->hash == headers[4].hash());
        REQUIRE(anchor->links[0]->next[0]->next.size() == 1);
        REQUIRE(anchor->links[0]->next[0]->next[0]->hash == headers[5].hash());
        REQUIRE(anchor->links[0]->next[0]->next[0]->next.empty());

        auto link4 = chain.links_[headers[4].hash()];
        auto [deepest_anchor, deepest_link] = chain.find_anchor(link4);
        REQUIRE(deepest_anchor == anchor);
        REQUIRE(deepest_link != nullptr);
    }

    INFO("connect to evicted link");
    {
        auto [penalty, requestMoreHeaders] =
            chain.accept_headers({headers[5], headers[6], headers[7]}, request_id, peer_id);

        REQUIRE(penalty == Penalty::kNoPenalty);
        REQUIRE(requestMoreHeaders == false);
        REQUIRE(chain.anchor_queue_.size() == 1);
        REQUIRE(chain.anchors_.size() == 1);
        REQUIRE(chain.links_.size() == 5);

        auto anchor = chain.anchors_[headers[3].parent_hash];
        auto link7 = chain.links_[headers[7].hash()];
        auto [deepest_anchor, deepest_link] = chain.find_anchor(link7);
        REQUIRE(deepest_anchor.has_value());
        REQUIRE(deepest_anchor == anchor);
        REQUIRE(deepest_link != nullptr);
    }
}

}  // namespace silkworm
