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

// Manually created to overcome grpcpp issue 24351 (https://github.com/grpc/grpc/issues/24351)

#include <silkworm/interfaces/remote/kv_mock.grpc.pb.h>

namespace remote {

class FixIssue24351_MockKVStub : public remote::MockKVStub {
 public:
  MOCK_METHOD3(AsyncVersion, ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>*(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncVersion, ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>*(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD1(Tx, ::grpc::ClientReaderWriterInterface< ::remote::Cursor, ::remote::Pair>*(::grpc::ClientContext* context));
  MOCK_METHOD3(AsyncTx, ::grpc::ClientAsyncReaderWriterInterface<::remote::Cursor, ::remote::Pair>*(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq, void* tag));
  MOCK_METHOD2(PrepareAsyncTx, ::grpc::ClientAsyncReaderWriterInterface<::remote::Cursor, ::remote::Pair>*(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq));
  MOCK_METHOD2(ReceiveStateChanges, ::grpc::ClientReaderInterface< ::remote::StateChange>*(::grpc::ClientContext* context, const ::google::protobuf::Empty& request));
  MOCK_METHOD4(AsyncReceiveStateChanges, ::grpc::ClientAsyncReaderInterface< ::remote::StateChange>*(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq, void* tag));
  MOCK_METHOD3(PrepareAsyncReceiveStateChanges, ::grpc::ClientAsyncReaderInterface< ::remote::StateChange>*(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncDomainGet, ::grpc::ClientAsyncResponseReaderInterface< ::remote::DomainGetReply>*(::grpc::ClientContext* context, const ::remote::DomainGetReq& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncDomainGet, ::grpc::ClientAsyncResponseReaderInterface< ::remote::DomainGetReply>*(::grpc::ClientContext* context, const ::remote::DomainGetReq& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncHistorySeek, ::grpc::ClientAsyncResponseReaderInterface< ::remote::HistorySeekReply>*(::grpc::ClientContext* context, const ::remote::HistorySeekReq& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncHistorySeek, ::grpc::ClientAsyncResponseReaderInterface< ::remote::HistorySeekReply>*(::grpc::ClientContext* context, const ::remote::HistorySeekReq& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncIndexRange, ::grpc::ClientAsyncResponseReaderInterface< ::remote::IndexRangeReply>*(::grpc::ClientContext* context, const ::remote::IndexRangeReq& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncIndexRange, ::grpc::ClientAsyncResponseReaderInterface< ::remote::IndexRangeReply>*(::grpc::ClientContext* context, const ::remote::IndexRangeReq& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncHistoryRange, ::grpc::ClientAsyncResponseReaderInterface< ::remote::Pairs>*(::grpc::ClientContext* context, const ::remote::HistoryRangeReq& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncHistoryRange, ::grpc::ClientAsyncResponseReaderInterface< ::remote::Pairs>*(::grpc::ClientContext* context, const ::remote::HistoryRangeReq& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncDomainRange, ::grpc::ClientAsyncResponseReaderInterface< ::remote::Pairs>*(::grpc::ClientContext* context, const ::remote::DomainRangeReq& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncDomainRange, ::grpc::ClientAsyncResponseReaderInterface< ::remote::Pairs>*(::grpc::ClientContext* context, const ::remote::DomainRangeReq& request, ::grpc::CompletionQueue* cq));
};

} // namespace remote
