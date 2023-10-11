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

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>

namespace silkworm::rpc {

class Writer {
  public:
    virtual ~Writer() = default;

    virtual void write(std::string_view content) = 0;
    virtual void close() {}
};

class NullWriter : public Writer {
  public:
    explicit NullWriter() = default;

    void write(std::string_view) override {
    }
};

class StringWriter : public Writer {
  public:
    StringWriter() = default;

    explicit StringWriter(std::size_t initial_capacity) {
        content_.reserve(initial_capacity);
    }

    void write(std::string_view content) override {
        content_.append(content);
    }

    const std::string& get_content() {
        return content_;
    }

  private:
    std::string content_;
};

class SocketWriter : public Writer {
  public:
    explicit SocketWriter(boost::asio::ip::tcp::socket& socket) : socket_(socket) {}

    void write(std::string_view content) override {
        boost::asio::write(socket_, boost::asio::buffer(content));
    }

  private:
    boost::asio::ip::tcp::socket& socket_;
};

class ChunksWriter : public Writer {
  public:
    explicit ChunksWriter(Writer& writer, std::size_t chunk_size = kDefaultChunkSize);

    void write(std::string_view content) override;
    void close() override;

  private:
    static const std::size_t kDefaultChunkSize = 0x800;

    void flush();

    Writer& writer_;
    const std::size_t chunk_size_;
    std::size_t available_;
    std::unique_ptr<char[]> buffer_;
};

class JsonChunksWriter : public Writer {
  public:
    explicit JsonChunksWriter(Writer& writer, std::size_t chunk_size = kDefaultChunkSize);

    void write(std::string_view content) override;
    void close() override;

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
