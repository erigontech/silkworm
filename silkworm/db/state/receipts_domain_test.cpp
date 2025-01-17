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

#include "receipts_domain.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::db::state {

TEST_CASE("ReceiptsDomainKeySnapshotsDecoder") {
    ReceiptsDomainKeySnapshotsDecoder decoder;
    decoder.decode_word(Bytes{1});
    CHECK(decoder.value == ReceiptsDomainKey::kCumulativeBlobGasUsedInBlockKey);

    CHECK_THROWS_AS(decoder.decode_word({}), std::runtime_error);
}

}  // namespace silkworm::db::state
