/*
   Copyright 2024 The Silkworm Authors

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

#include "timer.hpp"

namespace silkworm {

std::shared_ptr<Timer> Timer::create(const boost::asio::any_io_executor& executor,
                                     uint32_t interval,
                                     std::function<bool()> call_back,
                                     bool auto_start) {
    auto timer = std::shared_ptr<Timer>(new Timer{executor, interval, std::move(call_back)});
    if (auto_start) timer->start();
    return timer;
}

}  // namespace silkworm
