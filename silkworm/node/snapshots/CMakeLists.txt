#[[
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
]]

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

add_subdirectory(seg)

find_package(absl REQUIRED strings)
find_package(Boost REQUIRED headers) # for signals2
find_package(magic_enum REQUIRED)
find_package(Microsoft.GSL REQUIRED)

silkworm_library(
  silkworm_snapshots
  PUBLIC Microsoft.GSL::GSL silkworm_core silkworm_infra
  PRIVATE absl::strings Boost::headers magic_enum::magic_enum torrent-rasterbar silkworm_snapshots_seg
  EXCLUDE_REGEX "snapshots/seg"
)
