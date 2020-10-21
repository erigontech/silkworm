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

using namespace silkworm;

void test_logging()
{
    std::ofstream log_file("test.log");
    Logger logger(std::cerr, log_file, LogCrit);

    SILKWORM_LOG(LogCrit)  << "LogCrit"  << std::endl;
    SILKWORM_LOG(LogError) << "LogError" << std::endl;
    SILKWORM_LOG(LogWarn)  << "LogWarn"  << std::endl;
    SILKWORM_LOG(LogInfo)  << "LogInfo"  << std::endl;
    SILKWORM_LOG(LogDebug) << "LogDebug" << std::endl;
    SILKWORM_LOG(LogTrace) << "LogTrace" << std::endl;
}

int main() {
    test_logging();
}
