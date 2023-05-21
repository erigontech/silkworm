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

if(MSVC)
  add_compile_options(/wd4127) # Silence warnings about "conditional expression is constant" (abseil mainly)
  add_compile_options(/wd5030) # Silence warnings about GNU attributes
  add_compile_options(/wd4324) # Silence warning C4324: 'xxx': structure was padded due to alignment specifier
  add_compile_options(/wd4068) # Silence warning C4068: unknown pragma
  add_compile_options(/wd5030) # Silence warning C5030: unknown gnu/clang attribute
  add_compile_options(/W4) # Display all other un-silenced warnings

  add_link_options(/ignore:4099)
else()
  add_compile_options(-Werror -Wall -Wextra -pedantic)
  add_compile_options(-Wshadow -Wimplicit-fallthrough -Wsign-conversion)
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>)
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wnon-virtual-dtor>)
  add_compile_options(-Wno-missing-field-initializers)

  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wno-attributes)

    # gcc can issue bogus -Wmaybe-uninitialized warnings with std::optional
    # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80635
    add_compile_options(-Wno-error=maybe-uninitialized)
  endif()

  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_SYSTEM_NAME MATCHES "Darwin")
    add_compile_definitions(_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS)
    add_compile_options(-Wthread-safety)
  endif()
endif()
