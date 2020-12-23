add_library(keccak ethash/hash_types.h
                   ethash/hash_types.hpp
                   ethash/keccak.c
                   ethash/keccak.h
                   ethash/keccak.hpp)

target_include_directories(keccak PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
