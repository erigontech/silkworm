add_library(keccak hash_types.h
                   hash_types.hpp
                   keccak.c
                   keccak.h
                   keccak.hpp)

get_filename_component(SILKWORM_MAIN_DIR ../ ABSOLUTE)
target_include_directories(keccak PUBLIC ${SILKWORM_MAIN_DIR})
