// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <boost/asio/execution_context.hpp>

#include <silkworm/infra/concurrency/base_service.hpp>

namespace silkworm {

template <typename T>
class SharedService : public BaseService<SharedService<T>> {
  public:
    explicit SharedService(boost::asio::execution_context& owner) : BaseService<SharedService>(owner) {}

    void shutdown() override { shared_.reset(); }

    //! Explicitly make a *copy* of \code std::shared_ptr to be thread-safe
    void set_shared(std::shared_ptr<T> shared) {
        shared_ = std::move(shared);
    }
    T* ptr() { return shared_.get(); }

  private:
    std::shared_ptr<T> shared_;
};

template <typename T>
void add_shared_service(boost::asio::execution_context& context, std::shared_ptr<T> shared) {
    if (!has_service<SharedService<T>>(context)) {
        make_service<SharedService<T>>(context);
    }
    use_service<SharedService<T>>(context).set_shared(std::move(shared));
}

template <typename T>
T* use_shared_service(boost::asio::execution_context& context) {
    if (!has_service<SharedService<T>>(context)) {
        return nullptr;
    }
    return use_service<SharedService<T>>(context).ptr();
}

template <typename T>
T* must_use_shared_service(boost::asio::execution_context& context) {
    if (!has_service<SharedService<T>>(context)) {
        throw std::logic_error{"unregistered shared service: " + std::string{typeid(T).name()}};
    }
    return use_service<SharedService<T>>(context).ptr();
}

}  // namespace silkworm
