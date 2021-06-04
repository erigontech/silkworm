#[[
   Copyright 2021 The Silkworm Authors

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

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")

  add_definitions(-D_WIN32_WINNT=0x0602)  # Min Windows 8
  add_definitions(-DVC_EXTRALEAN)         # Process windows headers faster ...
  add_definitions(-DWIN32_LEAN_AND_MEAN)  # ... and prevent winsock mismatch with Boost's
  add_definitions(-DNOMINMAX)             # Prevent MSVC to tamper with std::min/std::max

  # LINK : fatal error LNK1104: cannot open file 'libboost_date_time-vc142-mt-x64-1_72.lib
  # is solved by this (issue only for MVC)
  add_definitions(-DBOOST_DATE_TIME_NO_LIB) 

  # Abseil triggeres some deprecation warnings
  add_compile_definitions(_SILENCE_CXX17_OLD_ALLOCATOR_MEMBERS_DEPRECATION_WARNING)
  add_compile_definitions(_SILENCE_CXX17_RESULT_OF_DEPRECATION_WARNING)

  add_compile_options(/MP)     # Enable parallel compilation
  add_compile_options(/EHa)    # Enable standard C++ unwinding

  add_compile_options(/wd4127) # Silence warnings about "conditional expression is constant" (abseil mainly)
  add_compile_options(/wd5030) # Silence warnings about GNU attributes
  add_compile_options(/wd4324) # Silence warning C4324: 'xxx': structure was padded due to alignment specifier
  add_compile_options(/wd4068) # Silence warning C4068: unknown pragma
  add_compile_options(/wd5030) # Silence warning C5030: unknown gnu/clang attribute
  add_compile_options(/W4)     # Display all other unsilenced warnings

  # Required for proper detection of __cplusplus
  # see https://docs.microsoft.com/en-us/cpp/build/reference/zc-cplusplus?view=msvc-160
  add_compile_options(/Zc:__cplusplus)

  add_link_options(/ignore:4099)

  if(CMAKE_BUILD_TYPE MATCHES "Release")
    add_compile_options(/GL)                                                  # Enable LTCG for faster builds
    set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} /LTCG")       # Enable LTCG for faster builds
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG")             # Enable LTCG for faster builds
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /OPT:REF /OPT:ICF") # Enable unused references removal
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /RELEASE")          # Enable RELEASE so that the executable file has its checksum set
  endif()

  if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /VERBOSE /TIME")    # Debug linker
  endif()

elseif("${CMAKE_CXX_COMPILER_ID}" MATCHES "GNU")

  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-g1)
  endif()

elseif("${CMAKE_CXX_COMPILER_ID}" MATCHES ".*Clang$")

  if(SILKWORM_CLANG_COVERAGE)
    add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
    add_link_options(-fprofile-instr-generate -fcoverage-mapping)
  endif()

  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-gline-tables-only)
  endif()

else ()

 message(WARNING "${CMAKE_CXX_COMPILER_ID} is not tested. Should you stumble into any issue please report at https://github.com/torquem-ch/silkworm/issues")

endif()
