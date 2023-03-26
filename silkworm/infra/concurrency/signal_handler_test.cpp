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

#include <csignal>

#include <catch2/catch.hpp>

#include <silkworm/infra/concurrency/signal_handler.hpp>

namespace silkworm {

// TODO fails on macOS
#ifndef __APPLE__
TEST_CASE("Signal Handler") {
    SignalHandler::init();
    std::raise(SIGINT);
    CHECK(SignalHandler::signalled());
    SignalHandler::reset();
    CHECK(SignalHandler::signalled() == false);
}
#endif  // __APPLE__

}  // namespace silkworm
