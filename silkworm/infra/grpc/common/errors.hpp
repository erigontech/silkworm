// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <boost/system/system_error.hpp>
#include <grpcpp/grpcpp.h>

namespace silkworm::rpc {

//! \details To raise a boost::system::system_error exception:
//! \code throw boost::system::system_error{rpc::to_system_code(grpc_status_code)};
boost::system::error_code to_system_code(::grpc::StatusCode);

}  // namespace silkworm::rpc
