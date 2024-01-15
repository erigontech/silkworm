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

#include <deque>
#include <memory>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>

namespace silkworm::rpc {

class StreamWriter {
  public:
    virtual ~StreamWriter() = default;

    virtual Task<std::size_t> write(std::string_view content) = 0;
    virtual Task<void> close() = 0;
};

class StringWriter : public StreamWriter {
  public:
    StringWriter() = default;

    explicit StringWriter(std::size_t initial_capacity) {
        content_.reserve(initial_capacity);
    }

    Task<std::size_t> write(std::string_view content) override {
        content_.append(content);
        co_return content.size();
    }

    Task<void> close() override { co_return; }

    const std::string& get_content() {
        return content_;
    }

  private:
    std::string content_;
};

const std::string kChunkSep{'\r', '\n'};                     // NOLINT(runtime/string)
const std::string kFinalChunk{'0', '\r', '\n', '\r', '\n'};  // NOLINT(runtime/string)

class ChunkWriter : public StreamWriter {
  public:
    explicit ChunkWriter(StreamWriter& writer);

    Task<std::size_t> write(std::string_view content) override;
    Task<void> close() override;

  private:
    StreamWriter& writer_;
};

}  // namespace silkworm::rpc
