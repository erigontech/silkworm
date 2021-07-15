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

#ifndef SILKWORM_COMMON_RLP_ERR_HPP_
#define SILKWORM_COMMON_RLP_ERR_HPP_

#include <magic_enum.hpp>

#include <silkworm/rlp/decode.hpp>

namespace silkworm::rlp {

class DecodingError : public std::exception {
  public:
    explicit DecodingError(DecodingResult err)
        : err_{magic_enum::enum_integer<DecodingResult>(err)},
          message_{"Decoding error : " + std::string(magic_enum::enum_name<DecodingResult>(err))} {};
    explicit DecodingError(DecodingResult err, const std::string& message)
        : err_{magic_enum::enum_integer<DecodingResult>(err)}, message_{message} {};
    virtual ~DecodingError() noexcept {};
    const char* what() const noexcept override { return message_.c_str(); }
    int err() const noexcept { return err_; }

  protected:
    int err_;
    std::string message_;
};

inline void err_handler(DecodingResult err) {
    if (err != DecodingResult::kOk) {
        throw DecodingError(err);
    }
}

}  // namespace silkworm::rlp

#endif  // !SILKWORM_COMMON_RLP_ERR_HPP_
