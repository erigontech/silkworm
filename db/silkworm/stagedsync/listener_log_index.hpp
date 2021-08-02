/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_DB_STAGEDSYNC_LISTENER_LOG_INDEX_HPP_
#define SILKWORM_DB_STAGEDSYNC_LISTENER_LOG_INDEX_HPP_

#include <string>
#include <unordered_map>

#include <cbor/decoder.h>

#include <silkworm/common/log.hpp>
#include <silkworm/db/bitmap.hpp>

namespace silkworm::stagedsync {

class listener_log_index : public cbor::listener {
  public:
    listener_log_index(uint64_t block_number, std::unordered_map<std::string, roaring::Roaring> *topics_map,
                       std::unordered_map<std::string, roaring::Roaring> *addrs_map, uint64_t *allocated_topics,
                       uint64_t *allocated_addrs_)
        : block_number_(block_number),
          topics_map_(topics_map),
          addrs_map_(addrs_map),
          allocated_topics_(allocated_topics),
          allocated_addrs_(allocated_addrs_){};

    void on_integer(int) override{};

    void on_bytes(unsigned char *data, int size) override {
        std::string key(byte_ptr_cast(data), size);
        if (size == kHashLength) {
            if (topics_map_->find(key) == topics_map_->end()) {
                topics_map_->emplace(key, roaring::Roaring());
            }
            topics_map_->at(key).add(block_number_);
            *allocated_topics_ += kHashLength;
        } else if (size == kAddressLength) {
            if (addrs_map_->find(key) == addrs_map_->end()) {
                addrs_map_->emplace(key, roaring::Roaring());
            }
            addrs_map_->at(key).add(block_number_);
            *allocated_addrs_ += kAddressLength;
        }
    }

    void on_string(std::string &) override{};

    void on_array(int) override {}

    void on_map(int) override{};

    void on_tag(unsigned int) override{};

    void on_special(unsigned int) override{};

    void on_bool(bool) override{};

    void on_null() override{};

    void on_undefined() override{};

    void on_error(const char *) override{};

    void on_extra_integer(unsigned long long, int) override{};

    void on_extra_tag(unsigned long long) override{};

    void on_extra_special(unsigned long long) override{};

    void on_double(double) override{};

    void on_float32(float) override{};

    void set_block_number(uint64_t block_number) { block_number_ = block_number; }

  private:
    uint64_t block_number_;
    std::unordered_map<std::string, roaring::Roaring> *topics_map_;
    std::unordered_map<std::string, roaring::Roaring> *addrs_map_;
    uint64_t *allocated_topics_;
    uint64_t *allocated_addrs_;
};

}  // namespace silkworm::stagedsync

#endif  // SILKWORM_DB_STAGEDSYNC_LISTENER_LOG_INDEX_HPP_
