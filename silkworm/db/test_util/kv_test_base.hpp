// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <agrpc/test.hpp>
#pragma GCC diagnostic pop
#include <gmock/gmock.h>

#include <silkworm/infra/grpc/test_util/grpc_responder.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>
#include <silkworm/interfaces/remote/kv_mock.grpc.pb.h>

namespace silkworm::db::test_util {

using testing::Expectation;
using testing::Return;

class KVTestBase : public silkworm::test_util::ContextTestBase {
  public:
    testing::Expectation expect_request_async_tx(bool ok) {
        return expect_request_async_tx(*stub_, ok);
    }

    testing::Expectation expect_request_async_statechanges(bool ok) {
        return expect_request_async_statechanges(*stub_, ok);
    }

    testing::Expectation expect_request_async_tx(remote::MockKVStub& stub, bool ok) {
        EXPECT_CALL(stub, PrepareAsyncTxRaw).WillOnce(Return(reader_writer_ptr_.release()));
        return EXPECT_CALL(reader_writer_, StartCall).WillOnce([&, ok](void* tag) {
            agrpc::process_grpc_tag(grpc_context_, tag, ok);
        });
    }

    testing::Expectation expect_request_async_statechanges(remote::MockKVStub& stub, bool ok) {
        EXPECT_CALL(stub, PrepareAsyncStateChangesRaw).WillOnce(Return(statechanges_reader_ptr_.release()));
        return EXPECT_CALL(*statechanges_reader_, StartCall).WillOnce([&, ok](void* tag) {
            agrpc::process_grpc_tag(grpc_context_, tag, ok);
        });
    }

    using StrictMockKVStub = testing::StrictMock<remote::MockKVStub>;
    using StrictMockKVTxAsyncReaderWriter = rpc::test::StrictMockAsyncReaderWriter<remote::Cursor, remote::Pair>;
    using StrictMockKVStateChangesAsyncReader = rpc::test::StrictMockAsyncReader<remote::StateChangeBatch>;

    StrictMockKVStub& stub() { return *stub_; }

  protected:
    //! Mocked stub of gRPC KV interface
    std::unique_ptr<StrictMockKVStub> stub_{std::make_unique<StrictMockKVStub>()};

    //! Mocked reader/writer for Tx bidi streaming RPC of gRPC KV interface
    std::unique_ptr<StrictMockKVTxAsyncReaderWriter> reader_writer_ptr_{
        std::make_unique<StrictMockKVTxAsyncReaderWriter>()};
    StrictMockKVTxAsyncReaderWriter& reader_writer_{*reader_writer_ptr_};

    //! Mocked reader for StateChanges server streaming RPC of gRPC KV interface
    std::unique_ptr<StrictMockKVStateChangesAsyncReader> statechanges_reader_ptr_{
        std::make_unique<StrictMockKVStateChangesAsyncReader>()};
    StrictMockKVStateChangesAsyncReader* statechanges_reader_{statechanges_reader_ptr_.get()};
};

}  // namespace silkworm::db::test_util
