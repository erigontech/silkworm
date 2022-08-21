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

#include <silkworm/db/access_layer.hpp>
#include <silkworm/downloader/internals/body_sequence.hpp>
#include <silkworm/downloader/internals/header_chain.hpp>
#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/downloader/sentry_client.hpp>

namespace silkworm {

class Message {
  public:
    virtual std::string name() const = 0;

    // execute: inbound message send a reply, outbound message send a request
    virtual void execute(db::ROAccess, HeaderChain&, BodySequence&, SentryClient&) = 0;

    virtual ~Message() = default;
};

}  // namespace silkworm
