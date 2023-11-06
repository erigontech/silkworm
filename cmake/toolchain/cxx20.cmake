#[[
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
]]

set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS NO)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)

cmake_policy(SET CMP0063 NEW)
cmake_policy(SET CMP0074 NEW)

if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "arm64")
  set(CMAKE_OSX_ARCHITECTURES
      "arm64"
      CACHE STRING ""
  )
endif()

set(CMAKE_OSX_DEPLOYMENT_TARGET
    "13.3"
    CACHE STRING ""
)
