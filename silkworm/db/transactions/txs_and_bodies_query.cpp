/*
   Copyright 2024 The Silkworm Authors

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

#include "txs_and_bodies_query.hpp"

#include <limits>
#include <sstream>
#include <stdexcept>

#include <magic_enum.hpp>

namespace silkworm::snapshots {

TxsAndBodiesQuery::Iterator::Iterator(
    std::shared_ptr<seg::Decompressor> txs_decoder,
    seg::Decompressor::Iterator tx_it,
    std::shared_ptr<seg::Decompressor> bodies_decoder,
    seg::Decompressor::Iterator body_it,
    BlockNum first_block_number,
    uint64_t first_tx_id,
    uint64_t expected_tx_count,
    std::string log_title)
    : txs_decoder_(std::move(txs_decoder)),
      tx_it_(std::move(tx_it)),
      bodies_decoder_(std::move(bodies_decoder)),
      body_it_(std::move(body_it)),
      first_tx_id_(first_tx_id),
      expected_tx_count_(expected_tx_count),
      log_title_(std::move(log_title)) {
    value_.block_number = first_block_number;
    value_.body_rlp = *body_it_;
    if (!value_.body_rlp.empty()) {
        decode_body_rlp(value_.body_rlp, value_.body);
    }
    value_.tx_buffer = *tx_it_;
}

void TxsAndBodiesQuery::Iterator::skip_bodies_until_tx_id(uint64_t tx_id) {
    while (!(tx_id < value_.body.base_txn_id + value_.body.txn_count)) {
        ++body_it_;
        if (body_it_ == bodies_decoder_->end()) {
            throw std::runtime_error{log_title_ + " not enough bodies"};
        }
        ++value_.block_number;
        value_.body_rlp = *body_it_;
        decode_body_rlp(value_.body_rlp, value_.body);
    }
}

TxsAndBodiesQuery::Iterator& TxsAndBodiesQuery::Iterator::operator++() {
    // check if already at the end
    if (!txs_decoder_) {
        return *this;
    }

    ++tx_it_;
    ++i_;

    if (tx_it_ != txs_decoder_->end()) {
        value_.tx_buffer = *tx_it_;
        skip_bodies_until_tx_id(first_tx_id_ + i_);
    } else {
        if (i_ != expected_tx_count_) {
            std::stringstream error;
            error << log_title_
                  << " tx count mismatch: expected=" + std::to_string(expected_tx_count_)
                  << " got=" << std::to_string(i_);
            throw std::runtime_error{error.str()};
        }

        // reset to match the end iterator
        body_it_ = bodies_decoder_->end();
        txs_decoder_.reset();
        bodies_decoder_.reset();
        value_ = {};
        value_.block_number = std::numeric_limits<uint64_t>::max();
    }

    return *this;
}

bool operator==(const TxsAndBodiesQuery::Iterator& lhs, const TxsAndBodiesQuery::Iterator& rhs) {
    return (lhs.txs_decoder_ == rhs.txs_decoder_) &&
           (!lhs.txs_decoder_ || (lhs.tx_it_ == rhs.tx_it_)) &&
           (lhs.bodies_decoder_ == rhs.bodies_decoder_) &&
           (!lhs.bodies_decoder_ || (lhs.body_it_ == rhs.body_it_));
}

void TxsAndBodiesQuery::Iterator::decode_body_rlp(ByteView body_rlp, BlockBodyForStorage& body) {
    auto decode_result = decode_stored_block_body(body_rlp, body);
    if (!decode_result) {
        std::stringstream error;
        error << log_title_
              << " cannot decode block " << value_.block_number
              << " body: " << to_hex(body_rlp)
              << " i: " << i_
              << " error: " << magic_enum::enum_name(decode_result.error());
        throw std::runtime_error{error.str()};
    }
}

TxsAndBodiesQuery::Iterator TxsAndBodiesQuery::begin() {
    std::string log_title = "TxsAndBodiesQuery for: " + txs_segment_path_.path().string();

    auto txs_decoder = std::make_shared<seg::Decompressor>(txs_segment_path_.path(), txs_segment_region_);
    txs_decoder->open();

    const auto tx_count = txs_decoder->words_count();
    if (tx_count != expected_tx_count_) {
        std::stringstream error;
        error << log_title
              << " tx count mismatch: expected=" << std::to_string(expected_tx_count_)
              << " got=" << std::to_string(tx_count);
        throw std::runtime_error{error.str()};
    }

    auto bodies_decoder = std::make_shared<seg::Decompressor>(bodies_segment_path_.path(), bodies_segment_region_);
    bodies_decoder->open();

    TxsAndBodiesQuery::Iterator it{
        txs_decoder,
        txs_decoder->begin(),
        bodies_decoder,
        bodies_decoder->begin(),
        bodies_segment_path_.block_from(),
        first_tx_id_,
        expected_tx_count_,
        log_title,
    };

    if (it->body_rlp.empty()) {
        throw std::runtime_error{log_title + " no bodies"};
    }

    return it;
}

TxsAndBodiesQuery::Iterator TxsAndBodiesQuery::end() {
    auto txs_decoder = std::make_shared<seg::Decompressor>(txs_segment_path_.path(), txs_segment_region_);
    auto bodies_decoder = std::make_shared<seg::Decompressor>(bodies_segment_path_.path(), bodies_segment_region_);
    return Iterator{
        {},
        txs_decoder->end(),
        {},
        bodies_decoder->end(),
        std::numeric_limits<uint64_t>::max(),
        first_tx_id_,
        expected_tx_count_,
        "TxsAndBodiesQuery::end",
    };
}

}  // namespace silkworm::snapshots
