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

#include <silkworm/interfaces/remote/ethbackend_mock.grpc.pb.h>

namespace remote {

class FixIssue24351_MockETHBACKENDStub : public MockETHBACKENDStub {
 public:
  MOCK_METHOD3(AsyncEtherbase, ::grpc::ClientAsyncResponseReaderInterface< ::remote::EtherbaseReply>*(::grpc::ClientContext* context, const ::remote::EtherbaseRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncEtherbase, ::grpc::ClientAsyncResponseReaderInterface< ::remote::EtherbaseReply>*(::grpc::ClientContext* context, const ::remote::EtherbaseRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncNetVersion, ::grpc::ClientAsyncResponseReaderInterface< ::remote::NetVersionReply>*(::grpc::ClientContext* context, const ::remote::NetVersionRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncNetVersion, ::grpc::ClientAsyncResponseReaderInterface< ::remote::NetVersionReply>*(::grpc::ClientContext* context, const ::remote::NetVersionRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncVersion, ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>*(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncVersion, ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>*(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncProtocolVersion, ::grpc::ClientAsyncResponseReaderInterface< ::remote::ProtocolVersionReply>*(::grpc::ClientContext* context, const ::remote::ProtocolVersionRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncProtocolVersion, ::grpc::ClientAsyncResponseReaderInterface< ::remote::ProtocolVersionReply>*(::grpc::ClientContext* context, const ::remote::ProtocolVersionRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncClientVersion, ::grpc::ClientAsyncResponseReaderInterface< ::remote::ClientVersionReply>*(::grpc::ClientContext* context, const ::remote::ClientVersionRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncClientVersion, ::grpc::ClientAsyncResponseReaderInterface< ::remote::ClientVersionReply>*(::grpc::ClientContext* context, const ::remote::ClientVersionRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD2(Subscribe, ::grpc::ClientReaderInterface< ::remote::SubscribeReply>*(::grpc::ClientContext* context, const ::remote::SubscribeRequest& request));
  MOCK_METHOD4(AsyncSubscribe, ::grpc::ClientAsyncReaderInterface< ::remote::SubscribeReply>*(::grpc::ClientContext* context, const ::remote::SubscribeRequest& request, ::grpc::CompletionQueue* cq, void* tag));
  MOCK_METHOD3(PrepareAsyncSubscribe, ::grpc::ClientAsyncReaderInterface< ::remote::SubscribeReply>*(::grpc::ClientContext* context, const ::remote::SubscribeRequest& request, ::grpc::CompletionQueue* cq));
};

} // namespace remote
