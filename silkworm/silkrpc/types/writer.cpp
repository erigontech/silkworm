/*
   Copyright 2022 The Silkrpc Authors

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

#include "writer.hpp"

#include <algorithm>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>

#include <silkworm/silkrpc/common/log.hpp>

namespace silkrpc {

const std::string chunck_sep{ '\r', '\n' }; // NOLINT(runtime/string)
const std::string final_chunck{ '0', '\r', '\n', '\r', '\n' }; // NOLINT(runtime/string)

ChunksWriter::ChunksWriter(Writer& writer, std::size_t chunck_size) :
    writer_(writer), chunck_size_(chunck_size), available_(chunck_size) {
    buffer_ = new char[chunck_size_];
    memset(buffer_, 0, chunck_size_);
}

void ChunksWriter::write(const std::string& content) {
    auto c_str = content.c_str();
    auto size = content.size();

    SILKRPC_DEBUG << "ChunksWriter::write available_: " << available_
        << " size: " << size
        << std::endl << std::flush;

    char *buffer_start = buffer_  + (chunck_size_ - available_);
    if (available_ > size) {
        std::strncpy(buffer_start, c_str, size);
        available_ -= size;
        return;
    }

    while (size > 0) {
        const auto count = std::min(available_, size);
        std::strncpy(buffer_start, c_str, count);
        size -= count;
        c_str += count;
        available_ -= count;
        if (available_ > 0) {
            break;
        }
        flush();

        buffer_start = buffer_;
    }
}

void ChunksWriter::close() {
    flush();
    writer_.write(final_chunck);
    writer_.close();
}

void ChunksWriter::flush() {
    auto size = chunck_size_ - available_;
    SILKRPC_DEBUG << "ChunksWriter::flush available_: " << available_
        << " size: " << size
        << std::endl << std::flush;

    if (size > 0) {
        std::stringstream stream;
        stream << std::hex << size << "\r\n";

        writer_.write(stream.str());
        std::string str{buffer_, size};
        writer_.write(str);
        writer_.write(chunck_sep);
    }
    available_ = chunck_size_;
    memset(buffer_, 0, chunck_size_);
}

} // namespace silkrpc
