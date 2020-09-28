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

#include "history_index.hpp"

#include <boost/endian/conversion.hpp>
#include <boost/iterator/counting_iterator.hpp>
#include <silkworm/common/util.hpp>

namespace silkworm::db::history_index {

constexpr size_t kItemLen{3};

static uint64_t elem(ByteView elements, uint64_t min_element, uint32_t i) {
    uint64_t x{min_element};
    x += (elements[i * kItemLen] & 0x7f) << 16;
    x += elements[i * kItemLen + 1] << 8;
    x += elements[i * kItemLen + 2];
    return x;
};

static SearchResult search_result(ByteView hi, uint32_t i) {
    uint64_t min_element{boost::endian::load_big_u64(hi.data())};
    ByteView elements{hi.substr(8)};
    return {
        elem(elements, min_element, i),       // change_block
        (elements[i * kItemLen] & 0x80) != 0  // new_record
    };
}

static size_t number_of_elements(ByteView hi) {
    if (hi.length() < 8) {
        throw DecodingError("minimal length of index chunk is 8");
    }
    if ((hi.length() - 8) % kItemLen) {
        throw DecodingError("length of index chunk should be 8 (mod 3)");
    }
    return (hi.length() - 8) / kItemLen;
}

static uint32_t lower_bound_index(ByteView hi, uint64_t v) {
    size_t n{number_of_elements(hi)};
    uint64_t min_element{boost::endian::load_big_u64(hi.data())};
    ByteView elements{hi.substr(8)};

    return *std::lower_bound(
        boost::counting_iterator<uint32_t>(0), boost::counting_iterator<uint32_t>(n), v,
        [elements, min_element](uint32_t i, uint64_t v) { return elem(elements, min_element, i) < v; });
}

std::optional<SearchResult> find(ByteView hi, uint64_t v) {
    uint32_t i{lower_bound_index(hi, v)};
    if (i == number_of_elements(hi)) {
        return {};
    } else {
        return search_result(hi, i);
    }
}

std::optional<SearchResult> find_previous(ByteView hi, uint64_t v) {
    uint32_t i{lower_bound_index(hi, v)};
    if (i == 0) {
        return {};
    } else {
        return search_result(hi, i - 1);
    }
}
}  // namespace silkworm::db::history_index
