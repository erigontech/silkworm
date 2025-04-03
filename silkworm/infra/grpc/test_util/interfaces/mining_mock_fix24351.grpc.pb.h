// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Manually created to overcome grpcpp issue 24351 (https://github.com/grpc/grpc/issues/24351)

#include <silkworm/interfaces/txpool/mining_mock.grpc.pb.h>

namespace txpool {

class FixIssue24351_MockMiningStub : public MockMiningStub {
 public:
  MOCK_METHOD3(AsyncVersion, ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>*(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncVersion, ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>*(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD4(AsyncOnPendingBlock, ::grpc::ClientAsyncReaderInterface< ::txpool::OnPendingBlockReply>*(::grpc::ClientContext* context, const ::txpool::OnPendingBlockRequest& request, ::grpc::CompletionQueue* cq, void* tag));
  MOCK_METHOD3(PrepareAsyncOnPendingBlock, ::grpc::ClientAsyncReaderInterface< ::txpool::OnPendingBlockReply>*(::grpc::ClientContext* context, const ::txpool::OnPendingBlockRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD4(AsyncOnMinedBlock, ::grpc::ClientAsyncReaderInterface< ::txpool::OnMinedBlockReply>*(::grpc::ClientContext* context, const ::txpool::OnMinedBlockRequest& request, ::grpc::CompletionQueue* cq, void* tag));
  MOCK_METHOD2(OnPendingLogs, ::grpc::ClientReaderInterface< ::txpool::OnPendingLogsReply>*(::grpc::ClientContext* context, const ::txpool::OnPendingLogsRequest& request));
  MOCK_METHOD4(AsyncOnPendingLogs, ::grpc::ClientAsyncReaderInterface< ::txpool::OnPendingLogsReply>*(::grpc::ClientContext* context, const ::txpool::OnPendingLogsRequest& request, ::grpc::CompletionQueue* cq, void* tag));
  MOCK_METHOD3(PrepareAsyncOnPendingLogs, ::grpc::ClientAsyncReaderInterface< ::txpool::OnPendingLogsReply>*(::grpc::ClientContext* context, const ::txpool::OnPendingLogsRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncGetWork, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::GetWorkReply>*(::grpc::ClientContext* context, const ::txpool::GetWorkRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncGetWork, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::GetWorkReply>*(::grpc::ClientContext* context, const ::txpool::GetWorkRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncSubmitWork, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::SubmitWorkReply>*(::grpc::ClientContext* context, const ::txpool::SubmitWorkRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncSubmitWork, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::SubmitWorkReply>*(::grpc::ClientContext* context, const ::txpool::SubmitWorkRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncSubmitHashRate, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::SubmitHashRateReply>*(::grpc::ClientContext* context, const ::txpool::SubmitHashRateRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncSubmitHashRate, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::SubmitHashRateReply>*(::grpc::ClientContext* context, const ::txpool::SubmitHashRateRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncHashRate, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::HashRateReply>*(::grpc::ClientContext* context, const ::txpool::HashRateRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncHashRate, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::HashRateReply>*(::grpc::ClientContext* context, const ::txpool::HashRateRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AsyncMining, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::MiningReply>*(::grpc::ClientContext* context, const ::txpool::MiningRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncMining, ::grpc::ClientAsyncResponseReaderInterface< ::txpool::MiningReply>*(::grpc::ClientContext* context, const ::txpool::MiningRequest& request, ::grpc::CompletionQueue* cq));
};

} // namespace txpool
