// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <memory>
#include <queue>

namespace silkworm::rpc::http {

inline constexpr int kDefaultMaxChunkSize = 2048;

class Chunker {
  public:
    Chunker(const Chunker&) = delete;

    Chunker() {
        current_chunk_.reserve(kDefaultMaxChunkSize);
    }

    ~Chunker() = default;

    void queue_data(const std::string& new_buffer) {
        size_t position = 0;

        // creates chunk: even if new:buffer is greater kDefaultMaxChunkSize
        while (position < new_buffer.size()) {
            size_t available_space = kDefaultMaxChunkSize - current_chunk_.size();
            size_t chunk_size = std::min(available_space, new_buffer.size() - position);

            current_chunk_.append(new_buffer, position, chunk_size);
            position += chunk_size;

            // one chunk is completed copy it in complet_chunk
            if (current_chunk_.size() == kDefaultMaxChunkSize) {
                complete_chunk_.push(current_chunk_);
                current_chunk_.clear();
                current_chunk_.reserve(kDefaultMaxChunkSize);
            }
        }
    }

    std::pair<std::string, bool> get_complete_chunk() {
        if (!complete_chunk_.empty()) {
            // at least one chunk is availble return it , indicating if first chunk or not
            auto ret_first_chunk = !first_chunk_completed_;
            first_chunk_completed_ = true;
            std::string chunk = complete_chunk_.front();
            complete_chunk_.pop();
            return std::make_pair(chunk, ret_first_chunk);
        }
        // queue is empty no chunk are available
        return std::make_pair("", false);
    }

    bool has_chunks() const {
        return !complete_chunk_.empty();
    }

    std::pair<std::string, bool> get_remainder() const {
        if (current_chunk_.empty()) {
            // no bytes are present on current_chunk so return empty string and indication if first chunk or not
            // we are in two possible cases: at least one completed chunk is already produced, or any chunk are produced
            return std::make_pair("", !first_chunk_completed_);
        }
        // returns the chunk
        return std::make_pair(current_chunk_, !first_chunk_completed_);
    }

  private:
    std::queue<std::string> complete_chunk_;
    std::string current_chunk_;
    bool first_chunk_completed_{false};
};

};  // namespace silkworm::rpc::http
