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

class Writer {
  public:
    virtual ~Writer() = default;

    virtual Task<std::size_t> write(std::string_view content) = 0;
    virtual Task<void> close() {
        co_return;
    }
};

class NullWriter : public Writer {
  public:
    explicit NullWriter() = default;

    Task<std::size_t> write(std::string_view content) override {
        co_return content.size();
    }
};

class StringWriter : public Writer {
  public:
    StringWriter() = default;

    explicit StringWriter(std::size_t initial_capacity) {
        content_.reserve(initial_capacity);
    }

    Task<std::size_t> write(std::string_view content) override {
        content_.append(content);
        co_return content.size();
    }

    const std::string& get_content() {
        return content_;
    }

  private:
    std::string content_;
};

class ChunksWriter : public Writer {
  public:
    explicit ChunksWriter(Writer& writer);

    Task<std::size_t> write(std::string_view content) override;
    Task<void> close() override;

  private:
    Writer& writer_;
};

class JsonChunksWriter : public Writer {
  public:
    explicit JsonChunksWriter(Writer& writer, std::size_t chunk_size = kDefaultChunkSize);

    Task<std::size_t> write(std::string_view content) override;
    Task<void> close() override;

  private:
    static const std::size_t kDefaultChunkSize = 0x800;

    Writer& writer_;
    bool chunk_open_ = false;
    const std::size_t chunk_size_;
    size_t room_left_in_chunck_;
    std::size_t written_;
    std::stringstream str_chunk_size_;
};

}  // namespace silkworm::rpc
