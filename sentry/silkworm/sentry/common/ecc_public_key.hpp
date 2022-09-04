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

#include <string>
#include <string_view>

#include <silkworm/common/base.hpp>

namespace silkworm::sentry::common {

class EccPublicKey {
  public:
    explicit EccPublicKey(Bytes data) : data_(std::move(data)) {}

    [[nodiscard]] ByteView data() const { return data_; }
    [[nodiscard]] Bytes::size_type size() const { return data_.size(); }

    [[nodiscard]] Bytes serialized_std() const;
    [[nodiscard]] Bytes serialized() const;
    [[nodiscard]] std::string hex() const;

    [[nodiscard]] static EccPublicKey deserialize_std(ByteView serialized_data);
    [[nodiscard]] static EccPublicKey deserialize(ByteView serialized_data);
    [[nodiscard]] static EccPublicKey deserialize_hex(std::string_view hex);

  private:
    Bytes data_;
};

}  // namespace silkworm::sentry::common
