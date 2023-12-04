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

#include <memory>

#include <agrpc/test.hpp>

#include <silkworm/interfaces/remote/kv_mock.grpc.pb.h>
#include <silkworm/rpc/test/context_test_base.hpp>
#include <silkworm/rpc/test/grpc_responder.hpp>

namespace silkworm::rpc::test {

using testing::Return;

struct KVTestBase : ContextTestBase {
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
    using StrictMockKVTxAsyncReaderWriter = test::StrictMockAsyncReaderWriter<remote::Cursor, remote::Pair>;
    using StrictMockKVStateChangesAsyncReader = test::StrictMockAsyncReader<remote::StateChangeBatch>;

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

}  // namespace silkworm::rpc::test
