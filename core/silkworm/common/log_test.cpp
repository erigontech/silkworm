/*
   Copyright 2020 The Silkworm Authors

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

#include <catch2/catch.hpp>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>

#include "util.hpp"

namespace silkworm {

namespace {
    std::ostringstream stream1, stream2;
    Logger logger(stream1, stream2);
    const std::string kInfix(R"(\[\d\d-\d\d|\d\d:\d\d:\d\d\.\d{3}\] )");

    bool test_log(std::string prefix, std::string infix, std::string suffix) {
        std::string string1(stream1.str());
        std::string string2(stream2.str());
        stream1.clear();
        stream1.str("");
        stream2.clear();
        stream2.str("");
        if (string1 != string2) return false;

        const std::string pattern = prefix + infix + suffix;
        const std::regex rx(pattern);
        return std::regex_search(string1, rx);
    }
}  // namespace

TEST_CASE("Logging") {
    // test true branch of macro
    logger.verbosity = LogTrace;
    SILKWORM_LOG_TO(logger, LogCritical) << "LogCritical" << std::endl;
    CHECK(test_log("CRIT ", kInfix, "LogCritical"));
    SILKWORM_LOG_TO(logger, LogError) << "LogError" << std::endl;
    CHECK(test_log("ERROR", kInfix, "LogError"));
    SILKWORM_LOG_TO(logger, LogWarn) << "LogWarn" << std::endl;
    CHECK(test_log("WARN ", kInfix, "LogWarn"));
    SILKWORM_LOG_TO(logger, LogInfo) << "LogInfo" << std::endl;
    CHECK(test_log("INFO ", kInfix, "LogInfo"));
    SILKWORM_LOG_TO(logger, LogDebug) << "LogDebug" << std::endl;
    CHECK(test_log("DEBUG", kInfix, "LogDebug"));
    SILKWORM_LOG_TO(logger, LogTrace) << "LogTrace" << std::endl;
    CHECK(test_log("TRACE", kInfix, "LogTrace"));

    // test false branch of macro
    logger.verbosity = LogDebug;
    SILKWORM_LOG_TO(logger, LogTrace) << "LogTrace" << std::endl;
    CHECK(test_log("", "", ""));
}

}  // namespace silkworm
