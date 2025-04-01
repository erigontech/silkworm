/*
   Copyright 2022 The Silkworm Authors

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
