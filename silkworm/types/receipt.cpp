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

#include "receipt.hpp"

#include <silkworm/rlp/encode.hpp>

namespace silkworm::rlp {

static Header header(const Receipt& r) {
  Header h;
  h.list = true;
  h.payload_length = 1;
  if (std::holds_alternative<evmc::bytes32>(r.post_state_or_status)) {
    h.payload_length += kHashLength;
  }
  h.payload_length += length(r.cumulative_gas_used);
  h.payload_length += length(full_view(r.bloom));
  h.payload_length += length(r.logs);
  return h;
}

void encode(Bytes& to, const Receipt& r) {
  encode_header(to, header(r));
  if (std::holds_alternative<evmc::bytes32>(r.post_state_or_status)) {
    encode(to, std::get<evmc::bytes32>(r.post_state_or_status));
  } else {
    encode(to, std::get<bool>(r.post_state_or_status));
  }
  encode(to, r.cumulative_gas_used);
  encode(to, full_view(r.bloom));
  encode(to, r.logs);
}
}  // namespace silkworm::rlp
