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

#include <silkworm/rpc/types/writer.hpp>

namespace silkworm::rpc {

class ChannelWriter : public Writer {
  public:
    enum class ResponseStatus {
        processing_continue,
        accepted,
        ok,
        created,
        no_content,
        multiple_choices,
        moved_permanently,
        moved_temporarily,
        not_modified,
        bad_request,
        unauthorized,
        forbidden,
        not_found,
        internal_server_error,
        not_implemented,
        bad_gateway,
        service_unavailable
    };

    struct Response {
        ResponseStatus status{ResponseStatus::ok};
        std::string content;
    };

    ChannelWriter() = default;
    ChannelWriter(const ChannelWriter&) = delete;
    ChannelWriter& operator=(const ChannelWriter&) = delete;

    virtual Task<void> write_rsp(Response& response) = 0;
};

}  // namespace silkworm::rpc
