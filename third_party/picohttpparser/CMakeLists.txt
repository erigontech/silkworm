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

add_library(pico_http_parser "picohttpparser/picohttpparser.c")

if(MSVC)
  target_compile_options(pico_http_parser PRIVATE /w)
else()
  target_compile_options(pico_http_parser PRIVATE -Wno-error)
endif(MSVC)

target_include_directories(pico_http_parser PUBLIC "picohttpparser")
