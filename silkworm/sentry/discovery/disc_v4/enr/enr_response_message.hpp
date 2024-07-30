/*
   Copyright 2023 The Silkworm Authors

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

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/discovery/enr/enr_record.hpp>

namespace silkworm::sentry::discovery::disc_v4::enr {

struct EnrResponseMessage {
    using EnrRecord = discovery::enr::EnrRecord;

    Bytes request_hash;
    EnrRecord record;

    [[nodiscard]] Bytes rlp_encode(const EccKeyPair& key_pair) const;
    [[nodiscard]] static EnrResponseMessage rlp_decode(ByteView data);

    static const uint8_t kId;

    class DecodeEnrRecordError : public std::runtime_error {
      public:
        explicit DecodeEnrRecordError(const std::exception& ex)
            : std::runtime_error(std::string("Failed to decode EnrResponseMessage.record: ") + ex.what()) {}
    };
};

}  // namespace silkworm::sentry::discovery::disc_v4::enr
