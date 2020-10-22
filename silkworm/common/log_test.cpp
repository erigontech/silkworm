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
#include "util.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <regex>

#include <catch2/catch.hpp>

namespace silkworm {

namespace {
    std::ostringstream stream1, stream2;
    Logger logger(stream1, stream2);
    const std::string infix(
        "\\w.\\w.\\w.\\w.-\\w.-\\w.\\w. \\w.\\w.:\\w.\\w.:\\w.\\w._UTC|"
        "log_test.cpp:\\d.\\d.| ");

    bool test_log(std::string prefix,std::string infix, std::string suffix)
    {
        std::string string1(stream1.str()), string2(stream2.str());
        stream1.clear();
        stream1.str("");
        stream2.clear();
        stream2.str("");
        if (string1 != string2) return false;

        const std::regex ix(prefix + infix + suffix);
        if (!std::regex_match(string1, ix)) return false;

        return true;
    }
}

bool test_logging() {

    logger.level(LogCrit);
    SILKWORM_LOG(LogCrit)  << "LogCrit"  << std::endl;
    test_log("CRIT ", infix, "LogCrit");
    SILKWORM_LOG(LogError) << "LogError" << std::endl;
    test_log("ERROR", infix, "LogError");
    SILKWORM_LOG(LogWarn)  << "LogWarn"  << std::endl;
    test_log("WARN ", infix, "LogWarn");
    SILKWORM_LOG(LogInfo)  << "LogInfo"  << std::endl;
    test_log("INFO ", infix, "LogInfo");
    SILKWORM_LOG(LogDebug) << "LogDebug" << std::endl;
    test_log("DEBUG", infix, "LogDebug");
    SILKWORM_LOG(LogTrace) << "LogTrace" << std::endl;
    test_log("TRACE", infix, "LogTrace");

    logger.level(LogTrace);
    SILKWORM_LOG(LogDebug) << "LogDebug" << std::endl;
    test_log("", "infix", "");

    return true;
}

TEST_CASE("Logging") {
    CHECK(test_logging() == true);
}

}
/*
int main() {
    silkworm::test_logging();
}
*/
