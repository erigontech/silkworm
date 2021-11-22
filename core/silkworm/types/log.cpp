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

#include "log.hpp"

#include <silkworm/rlp/encode_vector.hpp>

namespace silkworm ::rlp {

static Header header(const Log& l) {
    Header h;
    h.list = true;
    h.payload_length = kAddressLength + 1;
    h.payload_length += length(l.topics);
    h.payload_length += length(l.data);
    return h;
}

size_t length(const Log& l) {
    Header h{header(l)};
    return length_of_length(h.payload_length) + h.payload_length;
}

void encode(Bytes& to, const Log& l) {
    encode_header(to, header(l));
    encode(to, l.address);
    encode(to, l.topics);
    encode(to, l.data);
}

}  // namespace silkworm::rlp
