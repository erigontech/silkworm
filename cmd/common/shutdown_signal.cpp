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

#include "shutdown_signal.hpp"

#include <iostream>

#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::cmd::common {

static void log_signal(int signal_number) {
    std::cout << "\n";
    log::Info() << "Signal caught, number: " << signal_number;
}

void ShutdownSignal::on_signal(std::function<void(SignalNumber)> callback) {
    signals_.async_wait([callback = std::move(callback)](const boost::system::error_code& error, int signal_number) {
        if (error) {
            log::Error() << "ShutdownSignal.on_signal async_wait error: " << error;
            throw boost::system::system_error(error);
        }
        log_signal(signal_number);
        callback(signal_number);
    });
}

Task<ShutdownSignal::SignalNumber> ShutdownSignal::wait() {
    int signal_number = co_await signals_.async_wait(boost::asio::use_awaitable);
    log_signal(signal_number);
    co_return signal_number;
}

}  // namespace silkworm::cmd::common
