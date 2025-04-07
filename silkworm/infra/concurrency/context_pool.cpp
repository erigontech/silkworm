// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "context_pool.hpp"

namespace silkworm::concurrency {

std::ostream& operator<<(std::ostream& out, const Context& c) {
    out << c.to_string();
    return out;
}

std::string Context::to_string() const {
    const auto& c = *this;
    std::stringstream out;

    out << "io_context: " << c.ioc() << " id: " << c.id();
    return out.str();
}

Context::Context(size_t context_id)
    : context_id_{context_id},
      ioc_{std::make_shared<boost::asio::io_context>()},
      work_{boost::asio::make_work_guard(*ioc_)} {}

void Context::execute_loop() {
    SILK_DEBUG << "Context execution loop start [" << std::this_thread::get_id() << "]";
    ioc_->run();
    SILK_DEBUG << "Context execution loop end [" << std::this_thread::get_id() << "]";
}

void Context::stop() {
    ioc_->stop();
}

}  // namespace silkworm::concurrency
