// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <gmock/gmock.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>

namespace silkworm::rpc::test {

template <typename Reply>
class MockAsyncResponseReader : public ::grpc::ClientAsyncResponseReaderInterface<Reply> {
  public:
    MOCK_METHOD(void, StartCall, (), (override));
    MOCK_METHOD(void, ReadInitialMetadata, (void*), (override));
    MOCK_METHOD(void, Finish, (Reply*, ::grpc::Status*, void*), (override));
};

template <typename Reply>
using StrictMockAsyncResponseReader = testing::StrictMock<MockAsyncResponseReader<Reply>>;

template <typename Reply>
class MockAsyncReader : public ::grpc::ClientAsyncReaderInterface<Reply> {
  public:
    MOCK_METHOD(void, StartCall, (void*), (override));
    MOCK_METHOD(void, ReadInitialMetadata, (void*), (override));
    MOCK_METHOD(void, Read, (Reply*, void*), (override));
    MOCK_METHOD(void, Finish, (::grpc::Status*, void*), (override));
};

template <typename Reply>
using StrictMockAsyncReader = testing::StrictMock<MockAsyncReader<Reply>>;

template <typename Request, typename Reply>
class MockAsyncReaderWriter : public ::grpc::ClientAsyncReaderWriterInterface<Request, Reply> {
  public:
    MOCK_METHOD(void, StartCall, (void*), (override));
    MOCK_METHOD(void, ReadInitialMetadata, (void*), (override));
    MOCK_METHOD(void, Read, (Reply*, void*), (override));
    MOCK_METHOD(void, Write, (const Request&, void*), (override));
    MOCK_METHOD(void, WritesDone, (void*), (override));
    MOCK_METHOD(void, Finish, (::grpc::Status*, void*), (override));

    // gMock does not support mocking overloaded methods at runtime, but you can delegate from one another
    void Write(const Request& r, ::grpc::WriteOptions, void* tag) override {
        Write(r, tag);
    }
};

template <typename Request, typename Reply>
using StrictMockAsyncReaderWriter = testing::StrictMock<MockAsyncReaderWriter<Request, Reply>>;

}  // namespace silkworm::rpc::test
