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

#include "listener_log_index.hpp"

#include <silkworm/common/cast.hpp>

namespace silkworm::stagedsync {

void listener_log_index::on_bytes(unsigned char* data, int size) {
    std::string key(byte_ptr_cast(data), static_cast<size_t>(size));
    if (size == kHashLength) {
        if (topics_map_->find(key) == topics_map_->end()) {
            topics_map_->emplace(key, roaring::Roaring());
        }
        topics_map_->at(key).add(static_cast<uint32_t>(block_number_));
        *allocated_topics_ += kHashLength;
    } else if (size == kAddressLength) {
        if (addrs_map_->find(key) == addrs_map_->end()) {
            addrs_map_->emplace(key, roaring::Roaring());
        }
        addrs_map_->at(key).add(static_cast<uint32_t>(block_number_));
        *allocated_addrs_ += kAddressLength;
    }
}

}  // namespace silkworm::stagedsync
