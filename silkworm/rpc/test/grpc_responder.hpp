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

#include <gmock/gmock.h>
#include <grpcpp/grpcpp.h>

namespace silkworm::rpc::test {

template <typename Reply>
class MockAsyncResponseReader : public grpc::ClientAsyncResponseReaderInterface<Reply> {
  public:
    MOCK_METHOD(void, StartCall, (), (override));
    MOCK_METHOD(void, ReadInitialMetadata, (void*), (override));
    MOCK_METHOD(void, Finish, (Reply*, ::grpc::Status*, void*), (override));
};

template <typename Reply>
using StrictMockAsyncResponseReader = testing::StrictMock<MockAsyncResponseReader<Reply>>;

template <typename Reply>
class MockAsyncReader : public grpc::ClientAsyncReaderInterface<Reply> {
  public:
    MOCK_METHOD(void, StartCall, (void*), (override));
    MOCK_METHOD(void, ReadInitialMetadata, (void*), (override));
    MOCK_METHOD(void, Read, (Reply*, void*), (override));
    MOCK_METHOD(void, Finish, (::grpc::Status*, void*), (override));
};

template <typename Reply>
using StrictMockAsyncReader = testing::StrictMock<MockAsyncReader<Reply>>;

template <typename Request, typename Reply>
class MockAsyncReaderWriter : public grpc::ClientAsyncReaderWriterInterface<Request, Reply> {
  public:
    MOCK_METHOD(void, StartCall, (void*), (override));
    MOCK_METHOD(void, ReadInitialMetadata, (void*), (override));
    MOCK_METHOD(void, Read, (Reply*, void*), (override));
    MOCK_METHOD(void, Write, (const Request&, void*), (override));
    MOCK_METHOD(void, Write, (const Request&, ::grpc::WriteOptions, void*), (override));
    MOCK_METHOD(void, WritesDone, (void*), (override));
    MOCK_METHOD(void, Finish, (::grpc::Status*, void*), (override));
};

template <typename Request, typename Reply>
using StrictMockAsyncReaderWriter = testing::StrictMock<MockAsyncReaderWriter<Request, Reply>>;

}  // namespace silkworm::rpc::test
