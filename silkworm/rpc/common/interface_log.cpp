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

#include "interface_log.hpp"

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/spdlog.h>

#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::rpc {

class InterfaceLogImpl final {
  public:
    explicit InterfaceLogImpl(InterfaceLogSettings settings);
    ~InterfaceLogImpl() {
        flush();
    }

    bool dump_response() const {
        return dump_response_;
    }

    std::filesystem::path path() const {
        return file_path_;
    }

    template <typename... Args>
    void log(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        rotating_logger_->info(fmt, std::forward<Args>(args)...);
        if (auto_flush_) {
            rotating_logger_->flush();
        }
    }

    void log(std::string_view msg) {
        rotating_logger_->info(msg);
        if (auto_flush_) {
            rotating_logger_->flush();
        }
    }

    void flush() {
        rotating_logger_->flush();
    }

  private:
    std::string name_;
    bool auto_flush_;
    bool dump_response_;
    std::filesystem::path file_path_;
    size_t max_file_size_;
    size_t max_files_;
    std::shared_ptr<spdlog::sinks::rotating_file_sink_mt> rotating_sink_;
    std::shared_ptr<spdlog::logger> rotating_logger_;
};

InterfaceLogImpl::InterfaceLogImpl(InterfaceLogSettings settings)
    : name_{std::move(settings.ifc_name)},
      auto_flush_{settings.auto_flush},
      dump_response_{settings.dump_response},
      file_path_{settings.container_folder / std::filesystem::path{name_ + ".log"}},
      max_file_size_{settings.max_file_size_mb * kMebi},
      max_files_{settings.max_files},
      rotating_sink_{std::make_shared<spdlog::sinks::rotating_file_sink_mt>(file_path_.string(), max_file_size_, max_files_)},
      rotating_logger_{std::make_shared<spdlog::logger>(name_, rotating_sink_)} {
    ensure(!name_.empty(), "InterfaceLogImpl: name is empty");

    // Hard-code log level because we want all-or-nothing in interface log
    rotating_logger_->set_level(spdlog::level::info);

    // Customize log pattern to avoid unnecessary fields (log level, logger name)
    rotating_logger_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] %v");
}

//! Fixed-size header prepended to every log line: "[YYYY-MM-dd hh:mm:ss.mss] REQ|RSP -> "
const size_t InterfaceLog::kLogLineHeaderSize{33};

InterfaceLog::InterfaceLog(InterfaceLogSettings settings)
    : p_impl_{std::make_unique<InterfaceLogImpl>(std::move(settings))} {
}

// An explicit destructor is needed to avoid error:
// invalid application of 'sizeof' to an incomplete type 'silkworm::log::InterfaceLogImpl'
InterfaceLog::~InterfaceLog() {
    p_impl_->flush();
}

std::filesystem::path InterfaceLog::path() const {
    return p_impl_->path();
}

void InterfaceLog::log_req(std::string_view msg) {
    p_impl_->log("REQ -> {}", msg);
}

void InterfaceLog::log_rsp(std::string_view msg) {
    if (p_impl_->dump_response()) {
        p_impl_->log("RSP <- {}", msg);
    }
}

void InterfaceLog::flush() {
    p_impl_->flush();
}

}  // namespace silkworm::rpc
