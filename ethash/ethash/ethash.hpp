// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

// Modified by Silkworm's authors 2021

#pragma once
#ifndef ETHASH_ETHASH_HPP_
#define ETHASH_ETHASH_HPP_

#include <memory>
#include <optional>

#include "../../support/attributes.h"
#include "keccak.hpp"

namespace ethash {

// Internal constants:
constexpr static uint32_t revision = 23;
constexpr static uint32_t epoch_length = 30000;
constexpr static uint32_t light_cache_item_size = 64;
constexpr static uint32_t full_dataset_item_size = 128;
constexpr static uint32_t num_dataset_accesses = 64;
constexpr static uint32_t light_cache_init_size = 1 << 24;
constexpr static uint32_t light_cache_growth = 1 << 17;
constexpr static uint32_t light_cache_rounds = 3;
constexpr static uint32_t full_dataset_init_size = 1 << 30;
constexpr static uint32_t full_dataset_growth = 1 << 23;
constexpr static uint32_t full_dataset_item_parents = 256;
constexpr static uint32_t fnv_prime = 0x01000193u;
constexpr static uint32_t fnv_offset_basis = 0x811c9dc5u;

struct epoch_context {
    const uint32_t epoch_number;
    const uint32_t light_cache_num_items;
    const uint32_t full_dataset_num_items;
    const hash512* const light_cache;
};

struct result {
    hash256 final_hash;
    hash256 mix_hash;
};

namespace detail {

    using lookup_fn = hash1024 (*)(const epoch_context&, uint32_t);
    using hash_512_function = hash512 (*)(const uint8_t* data, size_t size);
    using build_light_cache_function = void (*)(hash512 cache[], int num_items, const hash256& seed);

    // hash512 calculate_dataset_item_512(const epoch_context& context, uint32_t index) noexcept;
    hash1024 calculate_dataset_item_1024(const epoch_context& context, uint32_t index) noexcept;

    hash512 hash_seed(const hash256& header, uint64_t nonce) noexcept;
    hash256 hash_mix(const epoch_context& context, const hash512& seed);
    hash256 hash_final(const hash512& seed, const hash256& mix) noexcept;

    void destroy_epoch_context(epoch_context* context) noexcept;

    /**
     * Creates the dag epoch context
     * @param epoch_number  The epoch number.
     * @return              A pointer to the created context
     */
    epoch_context* create_epoch_context(uint32_t epoch_number) noexcept;

}  // namespace detail

/**
 * Finds the largest prime number not greater than the provided upper bound.
 *
 * @param upper_bound  The upper bound.
 * @return  The largest prime number `p` such `p <= upper_bound`.
 *          In case `upper_bound <= 1`, returns 0.
 */
uint32_t find_largest_unsigned_prime(uint32_t upper_bound) noexcept;

/**
 * Calculates the number of items in the light cache for given epoch.
 *
 * This function will search for a prime number matching the criteria given
 * by the Ethash so the execution time is not constant. It takes ~ 0.01 ms.
 *
 * @param epoch_number  The epoch number.
 * @return              The number items in the light cache.
 */
uint32_t calculate_light_cache_num_items(uint32_t epoch_number) noexcept;

/**
 * Calculates the number of items in the full dataset for given epoch.
 *
 * This function will search for a prime number matching the criteria given
 * by the Ethash so the execution time is not constant. It takes ~ 0.05 ms.
 *
 * @param epoch_number  The epoch number.
 * @return              The number items in the full dataset.
 */
uint32_t calculate_full_dataset_num_items(uint32_t epoch_number) noexcept;

/**
 * Calculates the epoch seed hash.
 * @param epoch_number  The epoch number.
 * @return              The epoch seed hash.
 */
hash256 calculate_seed_from_epoch(uint32_t epoch_number) noexcept;

/**
 * Calculates the epoch number provided a seed hash.
 * @param seed          The hash256 seed
 * @return              The epoch number if found.
 */
std::optional<uint32_t> calculate_epoch_from_seed(const hash256& seed) noexcept;

/**
 * Performs a full ethash round with given nonce
 * @param context       The DAG epoch context.
 * @param header        The header hash of the block to be hashed
 *
 * @param nonce         The nonce to use
 * @return              A result struct holding both the final hash and the mix hash
 */
result hash(const epoch_context& context, const hash256& header, uint64_t nonce);

/**
 * Verifies only the final hash provided a header hash and a mix hash
 * It does not traverse the memory hard part and
 * assumes mix_hash is valid
 * @param header_hash
 * @param mix_hash      
 * @param nonce
 * @param boundary
 * @return              True / False
 */
bool verify_light(const hash256& header_hash, const hash256& mix_hash, uint64_t nonce,
                  const hash256& boundary) noexcept;

/**
 * Verifies the whole ethash outcome validating mix_hash and final_hash againts
 * the boundary. It does traverse the
 * memory hard part
 * @param header_hash
 * @param mix_hash      
 * @param nonce
 * @param boundary
 * @return              True / False
 */
bool verify_full(const epoch_context& context, const hash256& header_hash, const hash256& mix_hash, uint64_t nonce,
                 const hash256& boundary) noexcept;

using epoch_context_ptr = std::unique_ptr<epoch_context, decltype(&detail::destroy_epoch_context)>;
epoch_context_ptr create_epoch_context(int epoch_number) noexcept;

}  // namespace ethash

#endif  // !ETHASH_ETHASH_HPP_
