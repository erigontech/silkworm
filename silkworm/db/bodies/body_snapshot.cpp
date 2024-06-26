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

#include "body_snapshot.hpp"

#include <silkworm/infra/common/decoding_exception.hpp>

namespace silkworm::snapshots {

void encode_word_from_body(Bytes& word, const BlockBodyForStorage& body) {
    word = body.encode();
}

void decode_word_into_body(ByteView word, BlockBodyForStorage& body) {
    const auto result = decode_stored_block_body(word, body);
    success_or_throw(result, "decode_word_into_body: decode_stored_block_body error");
}

}  // namespace silkworm::snapshots
