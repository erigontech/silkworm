/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "log.hpp"

#include <regex>
#include <string>

#include <catch2/catch.hpp>

namespace silkworm {

namespace {

    std::ostringstream stream1, stream2;

    const std::regex colorPattern("(\\\x1b\\[[0-9;]{1,}m)");
    const std::string kInfix(R"(\[\d\d-\d\d\|\d\d:\d\d:\d\d\.\d{3} [A-Z]{3}\])");

    bool test_log(std::string prefix, std::string infix, std::string suffix) {
        std::string string1(stream1.str());
        std::string string2(stream2.str());
        stream1.clear();
        stream1.str("");
        stream2.clear();
        stream2.str("");
        if (string1 != string2) {
            return false;
        }
        if (string1.empty() && suffix.empty()) {
            return true;
        }
        const std::string pattern = " " + prefix + " " + infix + " " + suffix;
        const std::regex rx(pattern);
        string1 = std::regex_replace(string1, colorPattern, "");
        return std::regex_search(string1, rx);
    }
}  // namespace

TEST_CASE("Logging") {
    SILKWORM_LOG_STREAMS(stream1, stream2);

    // test true branch of macro
    log::set_verbosity(log::LogLevel::Trace);
    log::CriticalChannel() << "LogCritical";
    CHECK(test_log(" CRIT", kInfix, "LogCritical"));
    log::ErrorChannel() << "LogError";
    CHECK(test_log("ERROR", kInfix, "LogError"));
    log::WarningChannel() << "LogWarn";
    CHECK(test_log(" WARN", kInfix, "LogWarn"));
    log::InfoChannel() << "LogInfo";
    CHECK(test_log(" INFO", kInfix, "LogInfo"));
    log::DebugChannel() << "LogDebug";
    CHECK(test_log("DEBUG", kInfix, "LogDebug"));
    log::TraceChannel() << "LogTrace";
    CHECK(test_log("TRACE", kInfix, "LogTrace"));

    // test false branch of macro
    log::set_verbosity(log::LogLevel::Debug);
    log::TraceChannel() << "LogTrace";
    CHECK(test_log("", "", ""));
}

}  // namespace silkworm
