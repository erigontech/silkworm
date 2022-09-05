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

#pragma once

#include <memory>

#include <silkworm/common/base.hpp>

class Keccak;

namespace silkworm::sentry::rlpx::crypto {

class Sha3Hasher final {
  public:
    Sha3Hasher();
    ~Sha3Hasher();

    void update(ByteView data);
    [[nodiscard]] Bytes hash();

  private:
    std::unique_ptr<Keccak> impl_;
};

}  // namespace silkworm::sentry::rlpx::crypto
