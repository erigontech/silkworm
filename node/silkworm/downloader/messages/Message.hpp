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

#ifndef SILKWORM_MESSAGE_HPP
#define SILKWORM_MESSAGE_HPP

#include <silkworm/downloader/internals/types.hpp>

namespace silkworm {

class Message {
  public:
    virtual std::string name() const = 0;

    virtual void execute() = 0;  // inbound message send a reply, outbound message send a request

    virtual ~Message() = default;
};

}  // namespace silkworm

#endif  // SILKWORM_MESSAGE_HPP
