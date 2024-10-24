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

#include "outbound_block_headers.hpp"

#include <sstream>

#include <silkworm/infra/common/log.hpp>

namespace silkworm {

void OutboundBlockHeaders::execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) {
}

Bytes OutboundBlockHeaders::message_data() const {
    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    return rlp_encoding;
}

std::string OutboundBlockHeaders::content() const {
    std::stringstream content;
    log::prepare_for_logging(content);
    content << packet_;
    return content.str();
}

}  // namespace silkworm
