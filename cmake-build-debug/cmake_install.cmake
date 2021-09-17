# Install script for directory: /Users/giuliorebuffo/forking/silkworm

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/Library/Developer/CommandLineTools/usr/bin/objdump")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/Users/giuliorebuffo/forking/silkworm/cmake-build-debug/libff/cmake_install.cmake")
  include("/Users/giuliorebuffo/forking/silkworm/cmake-build-debug/cbor-cpp/cmake_install.cmake")
  include("/Users/giuliorebuffo/forking/silkworm/cmake-build-debug/evmone/evmc/cmake_install.cmake")
  include("/Users/giuliorebuffo/forking/silkworm/cmake-build-debug/libmdbx/cmake_install.cmake")
  include("/Users/giuliorebuffo/forking/silkworm/cmake-build-debug/core/cmake_install.cmake")
  include("/Users/giuliorebuffo/forking/silkworm/cmake-build-debug/interfaces/cmake_install.cmake")
  include("/Users/giuliorebuffo/forking/silkworm/cmake-build-debug/node/cmake_install.cmake")
  include("/Users/giuliorebuffo/forking/silkworm/cmake-build-debug/cmd/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/Users/giuliorebuffo/forking/silkworm/cmake-build-debug/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
