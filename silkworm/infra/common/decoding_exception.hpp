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

#include <stdexcept>
#include <string>

#include <silkworm/core/common/decoding_result.hpp>

namespace silkworm {

class DecodingException : public std::runtime_error {
  public:
    explicit DecodingException(DecodingError err, const std::string& message = "");

    DecodingError err() const noexcept { return err_; }

  private:
    DecodingError err_;
};

template <class T>
inline void success_or_throw(const tl::expected<T, DecodingError>& res, const std::string& error_message = "") {
    if (!res) {
        throw DecodingException(res.error(), error_message);
    }
}

template <class T>
inline T unwrap_or_throw(tl::expected<T, DecodingError> res, const std::string& error_message = "") {
    success_or_throw(res, error_message);
    return std::move(*res);
}

}  // namespace silkworm
