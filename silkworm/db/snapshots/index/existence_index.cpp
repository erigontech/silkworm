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

#include "existence_index.hpp"

#include <fstream>

namespace silkworm::snapshots::index {

ExistenceIndex::Reader::Reader(std::filesystem::path index_file_path)
    : index_file_path_(std::move(index_file_path)) {
    if (std::filesystem::file_size(index_file_path_) == 0) {
        throw std::runtime_error("index " + index_file_path_.filename().string() + " is empty");
    }
    std::ifstream index_file_stream{index_file_path_, std::ios::in | std::ios::binary};
    filter_ = BloomFilter::read_from(index_file_stream);
}

void ExistenceIndex::Reader::add_hash(uint64_t hash) {
    filter_->add_hash(hash);
}

bool ExistenceIndex::Reader::contains_hash(uint64_t hash) {
    return filter_->contains_hash(hash);
}

}  // namespace silkworm::snapshots::index
