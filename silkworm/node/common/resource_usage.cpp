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

#include "resource_usage.hpp"

#include <chrono>

#include <boost/asio/experimental/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/mem_usage.hpp>
#include <silkworm/infra/common/stopwatch.hpp>

namespace silkworm {

using namespace std::chrono_literals;
using std::chrono::steady_clock;

const auto kResourceUsageInterval{300s};

ResourceUsageLog::ResourceUsageLog(NodeSettings& settings) : settings_{settings}, timer_{settings_.asio_context} {}

Task<void> ResourceUsageLog::run() {
    const auto start_time = steady_clock::now();
    while (true) {
        try {
            timer_.expires_after(kResourceUsageInterval);
            co_await timer_.async_wait(boost::asio::use_awaitable);

            log::Info("Resource usage", {"mem", human_size(os::get_mem_usage()),
                                         "chain", human_size(settings_.data_directory->chaindata().size()),
                                         "etl-tmp", human_size(settings_.data_directory->etl().size()),
                                         "uptime", StopWatch::format(steady_clock::now() - start_time)});
        } catch (const boost::system::system_error& ex) {
            if (ex.code() == boost::system::errc::operation_canceled) {
                co_return;
            }
        }
    }
}

}  // namespace silkworm
