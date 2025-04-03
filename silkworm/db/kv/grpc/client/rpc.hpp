// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <agrpc/client_rpc.hpp>
#pragma GCC diagnostic pop
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/interfaces/remote/kv.grpc.pb.h>

namespace silkworm::db::kv::grpc::client {

using TxRpc = boost::asio::use_awaitable_t<>::as_default_on_t<agrpc::ClientRPC<&::remote::KV::StubInterface::PrepareAsyncTx>>;

}  // namespace silkworm::db::kv::grpc::client
