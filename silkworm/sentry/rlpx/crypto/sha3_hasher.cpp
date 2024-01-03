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

#include "sha3_hasher.hpp"

#include <keccak.h>

#include <silkworm/core/common/util.hpp>

namespace silkworm::sentry::rlpx::crypto {

Sha3Hasher::Sha3Hasher() : impl_(std::make_unique<Keccak>()) {
}

Sha3Hasher::~Sha3Hasher() = default;

void Sha3Hasher::update(ByteView data) {
    impl_->add(data.data(), data.size());
}

Bytes Sha3Hasher::hash() {
    return from_hex(impl_->getHash()).value();
}

}  // namespace silkworm::sentry::rlpx::crypto
