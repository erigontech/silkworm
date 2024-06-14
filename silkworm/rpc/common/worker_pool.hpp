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

#pragma once

#include <thread>

#include <boost/asio/thread_pool.hpp>

namespace silkworm::rpc {

//! Default number of threads in worker pool (i.e. dedicated to heavier tasks)
inline const auto kDefaultNumWorkers{std::thread::hardware_concurrency() / 2};

//! Pool of worker threads dedicated to heavier tasks
using WorkerPool = boost::asio::thread_pool;

}  // namespace silkworm::rpc
