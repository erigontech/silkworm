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

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::rlpx {

struct Protocol {
    virtual ~Protocol() = default;
    virtual std::pair<std::string, uint8_t> capability() = 0;
    virtual Message first_message() = 0;
    virtual void handle_peer_first_message(const Message& message) = 0;
    virtual bool is_compatible_enr_entry(std::string_view name, ByteView data) = 0;

    class IncompatiblePeerError : public std::runtime_error {
      public:
        IncompatiblePeerError() : std::runtime_error("rlpx::Protocol: incompatible peer") {}
    };
};

}  // namespace silkworm::sentry::rlpx
