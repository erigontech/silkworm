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

#include <silkworm/interfaces/txpool/txpool_mock.grpc.pb.h>

namespace txpool {

class FixIssue24351_MockTxpoolStub : public MockTxpoolStub {
 public:
  MOCK_METHOD3(AsyncVersion, ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>*(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncVersion, ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>*(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncFindUnknown, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::TxHashes>*(::grpc::ClientContext* context, const ::txpool::TxHashes& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncFindUnknown, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::TxHashes>*(::grpc::ClientContext* context, const ::txpool::TxHashes& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncAdd, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::AddReply>*(::grpc::ClientContext* context, const ::txpool::AddRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncAdd, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::AddReply>*(::grpc::ClientContext* context, const ::txpool::AddRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncTransactions, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::TransactionsReply>*(::grpc::ClientContext* context, const ::txpool::TransactionsRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncTransactions, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::TransactionsReply>*(::grpc::ClientContext* context, const ::txpool::TransactionsRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD2(OnAdd, ::grpc::ClientReaderInterface< ::txpool::OnAddReply>*(::grpc::ClientContext* context, const ::txpool::OnAddRequest& request));
  MOCK_METHOD4(AsyncOnAdd, ::grpc::ClientAsyncReaderInterface< ::txpool::OnAddReply>*(::grpc::ClientContext* context, const ::txpool::OnAddRequest& request, ::grpc::CompletionQueue* cq, void* tag));
  MOCK_METHOD3(PrepareAsyncOnAdd, ::grpc::ClientAsyncReaderInterface< ::txpool::OnAddReply>*(::grpc::ClientContext* context, const ::txpool::OnAddRequest& request, ::grpc::CompletionQueue* cq));
};

} // namespace txpool

