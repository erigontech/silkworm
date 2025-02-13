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

#pragma once

#include "codec.hpp"

namespace silkworm::datastore::kvdb {

struct BigEndianU64Codec : public Codec {
    uint64_t value{0};
    Bytes data;

    BigEndianU64Codec() = default;
    explicit BigEndianU64Codec(uint64_t value1) : value{value1} {}
    ~BigEndianU64Codec() override = default;

    Slice encode() override;
    void decode(Slice slice) override;
};

static_assert(EncoderConcept<BigEndianU64Codec>);
static_assert(DecoderConcept<BigEndianU64Codec>);

}  // namespace silkworm::datastore::kvdb
