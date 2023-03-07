/*
    Copyright 2020 The Silkrpc Authors

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

#include "error.hpp"

#include <utility>

class generic_error_category : public std::error_category {
public:
    const char* name() const noexcept override;
    std::string message(int ev) const override;

    void set_error(int error_code, std::string&& error_message) {
        error_code_ = error_code;
        error_message_ = error_message;
    }

private:
    int error_code_;
    std::string error_message_;
};

const char* generic_error_category::name() const noexcept { return "grpc"; }

std::string generic_error_category::message(int ev) const { return error_message_; }

std::error_code make_error_code(int error_code, std::string&& error_message) {
    thread_local generic_error_category tls_error_category{};
    tls_error_category.set_error(error_code, std::move(error_message));
    return {error_code, tls_error_category};
}
