// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "error.hpp"

#include <utility>

class GrpcErrorCategory : public std::error_category {
  public:
    const char* name() const noexcept override;
    std::string message(int ev) const override;

    void set_error(std::string error_message) {
        error_message_ = std::move(error_message);
    }

  private:
    std::string error_message_;
};

const char* GrpcErrorCategory::name() const noexcept { return "grpc"; }

std::string GrpcErrorCategory::message(int /*ev*/) const { return error_message_; }

std::error_code make_error_code(int error_code, std::string error_message) {
    thread_local GrpcErrorCategory tls_error_category{};
    tls_error_category.set_error(std::move(error_message));
    return {error_code, tls_error_category};
}
