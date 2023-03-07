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

#pragma once

#include <memory>
#include <string>

#include <boost/asio/awaitable.hpp>
#include <gmock/gmock.h>

#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/core/common/base.hpp>

namespace silkrpc::test {

class MockDatabaseReader : public core::rawdb::DatabaseReader {
public:
    MOCK_METHOD((boost::asio::awaitable<KeyValue>), get, (const std::string&, const silkworm::ByteView&), (const));
    MOCK_METHOD((boost::asio::awaitable<silkworm::Bytes>), get_one, (const std::string&, const silkworm::ByteView&), (const));
    MOCK_METHOD((boost::asio::awaitable<std::optional<silkworm::Bytes>>), get_both_range,
                (const std::string&, const silkworm::ByteView&, const silkworm::ByteView&), (const));
    MOCK_METHOD((boost::asio::awaitable<void>), walk, (const std::string&, const silkworm::ByteView&, uint32_t, core::rawdb::Walker),
                (const));
    MOCK_METHOD((boost::asio::awaitable<void>), for_prefix, (const std::string&, const silkworm::ByteView&, core::rawdb::Walker),
                (const));
};

}  // namespace silkrpc::test

