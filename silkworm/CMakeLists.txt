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

# Silkworm itself
add_subdirectory(core)

if(NOT SILKWORM_CORE_ONLY)
  add_subdirectory(interfaces)
  add_subdirectory(infra)
  add_subdirectory(db)
  add_subdirectory(rpc)
  add_subdirectory(sentry)
  add_subdirectory(sync)
  add_subdirectory(node)
  add_subdirectory(capi)
endif()

if(SILKWORM_WASM_API)
  add_subdirectory(wasm)
endif()
