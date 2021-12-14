/*
   Copyright 2021 The Silkworm Authors

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

#include "receive_messages.hpp"

namespace silkworm::rpc {

ReceiveMessages::ReceiveMessages(int scope)
    : OutStreamingCall("ReceiveMessages", &sentry::Sentry::Stub::Messages, {}) {
    if (scope & SentryClient::Scope::BlockAnnouncements) {  // previously received with RecvMessages
        request_.add_ids(sentry::MessageId::BLOCK_HEADERS_66);
        request_.add_ids(sentry::MessageId::BLOCK_BODIES_66);
        request_.add_ids(sentry::MessageId::NEW_BLOCK_HASHES_66);
        request_.add_ids(sentry::MessageId::NEW_BLOCK_66);
    }

    if (scope & SentryClient::Scope::BlockRequests) {  // previously received with RecvUploadMessages
        request_.add_ids(sentry::MessageId::GET_BLOCK_HEADERS_66);
        request_.add_ids(sentry::MessageId::GET_BLOCK_BODIES_66);
    }
}

}  // namespace silkworm::rpc