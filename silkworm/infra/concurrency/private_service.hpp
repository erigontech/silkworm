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

#include <boost/asio/execution_context.hpp>

#include <silkworm/infra/concurrency/base_service.hpp>

namespace silkworm {

template <typename T>
class PrivateService : public BaseService<PrivateService<T>> {
  public:
    explicit PrivateService(boost::asio::execution_context& owner) : BaseService<PrivateService>(owner) {}

    void shutdown() override { unique_.reset(); }

    //! Explicitly *take ownership* of \code std::unique_ptr to enforce isolation
    void set_unique(std::unique_ptr<T> unique) {
        unique_ = std::move(unique);
    }
    T* ptr() { return unique_.get(); }

  private:
    std::unique_ptr<T> unique_;
};

template <typename T>
void add_private_service(boost::asio::execution_context& context, std::unique_ptr<T> unique) {
    if (!has_service<PrivateService<T>>(context)) {
        make_service<PrivateService<T>>(context);
    }
    use_service<PrivateService<T>>(context).set_unique(std::move(unique));
}

template <typename T>
T* use_private_service(boost::asio::execution_context& context) {
    if (!has_service<PrivateService<T>>(context)) {
        return nullptr;
    }
    return use_service<PrivateService<T>>(context).ptr();
}

template <typename T>
T* must_use_private_service(boost::asio::execution_context& context) {
    if (!has_service<PrivateService<T>>(context)) {
        throw std::logic_error{"unregistered private service: " + std::string{typeid(T).name()}};
    }
    return use_service<PrivateService<T>>(context).ptr();
}

}  // namespace silkworm
