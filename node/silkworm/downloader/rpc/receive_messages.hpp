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

#include <p2psentry/sentry.grpc.pb.h>

#include <silkworm/downloader/internals/grpc_sync_client.hpp>

namespace silkworm::rpc {

class ReceiveMessages : public rpc::OutStreamingCall<sentry::Sentry, sentry::MessagesRequest, sentry::InboundMessage> {
  public:
    ReceiveMessages(int scope);

    enum Scope {
        BlockRequests = 0x01,
        BlockAnnouncements = 0x02,
        Other = 0x04
    };
    // enum values enable bit masking, for example: cope = BlockRequests & BlockAnnouncements

    static Scope scope(const sentry::InboundMessage&);
};

}  // namespace silkworm::rpc
