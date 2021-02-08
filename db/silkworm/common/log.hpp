/*
   Copyright 2020 - 2021 The Silkworm Authors

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

#ifndef SILKWORM_COMMON_LOG_H_
#define SILKWORM_COMMON_LOG_H_

#include <silkworm/common/tee.hpp>
#include <mutex>

namespace silkworm {

// stream labeled logging output - e.g.
//	  SILKWORM_LOG(LogInfo) << "All your " << num_bases << " base are belong to us\n";
//
#define SILKWORM_LOG(level_) if ((level_) < detail::log_verbosity_) {} else detail::log_(level_)

// change the logging verbosity level - default level is LogInfo
//
#define SILKWORM_LOG_VERBOSITY(level_) (detail::log_verbosity_ = (level_))

// available verbosity levels
enum LogLevels { LogTrace, LogDebug, LogInfo, LogWarn, LogError, LogCritical, LogNone };

// change the logging output streams - default is (cerr, null_stream())
//
#define SILKWORM_LOG_STREAMS(stream1_, stream2_) detail::log_set_streams_((stream1_), (stream2_));

// silence
std::ostream& null_stream();

//
// Below are for access via macros ONLY :(
//
namespace detail {
    extern LogLevels log_verbosity_;
    void log_set_streams_(std::ostream & o1, std::ostream & o2);
    class log_ {
      public:
       log_(LogLevels level_) : level_(level_) { log_mtx_.lock(); }
        ~log_() { log_mtx_.unlock(); }
        std::ostream& header_(LogLevels);
        template <class T> std::ostream& operator<< (const T & message) {
            return header_(level_) << message;
        }
      private:
        LogLevels level_;
        static std::mutex log_mtx_;
    };
}  // namespace namespace detail

}  // namespace silkworm

#endif	// SILKWORM_COMMON_LOG_H_
