file(GLOB_RECURSE ETHASH_SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp" "*.c" "*.h")
add_library(ethash ${ETHASH_SRC})
target_include_directories(ethash PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
