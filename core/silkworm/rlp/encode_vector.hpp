/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_RLP_ENCODE_VECTOR_HPP_
#define SILKWORM_RLP_ENCODE_VECTOR_HPP_

#include <vector>

#include <silkworm/rlp/encode.hpp>

namespace silkworm::rlp {

namespace detail {
    template <class T>
    Header rlp_header(const std::vector<T>& v) {
        Header h{/*list=*/true, /*payload_length=*/0};
        for (const T& x : v) {
            h.payload_length += length(x);
        }
        return h;
    }
}  // namespace detail

template <class T>
size_t length(const std::vector<T>& v) {
    const size_t payload_length{detail::rlp_header(v).payload_length};
    return length_of_length(payload_length) + payload_length;
}

template <class T>
void encode(Bytes& to, const std::vector<T>& v) {
    const Header h{detail::rlp_header(v)};
    to.reserve(to.size() + length_of_length(h.payload_length) + h.payload_length);
    encode_header(to, h);
    for (const T& x : v) {
        encode(to, x);
    }
}

}  // namespace silkworm::rlp

#endif  // SILKWORM_RLP_ENCODE_VECTOR_HPP_
