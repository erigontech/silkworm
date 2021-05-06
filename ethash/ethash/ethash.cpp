// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

// Modified by Silkworm's authors 2021

#include "ethash.hpp"

namespace ethash {

namespace detail {

    /**
     * The implementation of FNV-1 hash.
     *
     * See https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function#FNV-1_hash.
     */
    NO_SANITIZE("unsigned-integer-overflow")
    static inline uint32_t fnv1(uint32_t u, uint32_t v) noexcept { return (u * fnv_prime) ^ v; }
    static inline hash512 fnv1_512(const hash512& a, const hash512& b) noexcept {
        hash512 ret{};
        for (size_t i{0}; i < sizeof(ret) / sizeof(ret.word32s[0]); ++i) {
            ret.word32s[i] = fnv1(a.word32s[i], b.word32s[i]);
        }
        return ret;
    }
    static inline hash512 xor_512(const hash512& x, const hash512& y) noexcept {
        hash512 z;
        for (size_t i{0}; i < sizeof(z) / sizeof(z.word64s[0]); ++i) {
            z.word64s[i] = x.word64s[i] ^ y.word64s[i];
        }
        return z;
    }

    struct item_state {
        const hash512* const cache;
        const uint32_t num_cache_items;
        const uint32_t seed;

        hash512 mix;

        ALWAYS_INLINE item_state(const epoch_context& context, uint32_t index) noexcept
            : cache{context.light_cache}, num_cache_items{context.light_cache_num_items}, seed{index} {
            mix = cache[index % num_cache_items];
            mix.word32s[0] ^= le::uint32(seed);
            mix = le::uint32s(keccak512(mix));
        }

        ALWAYS_INLINE void update(uint32_t round) noexcept {
            static constexpr size_t num_words = sizeof(mix) / sizeof(uint32_t);
            const uint32_t t = fnv1(seed ^ round, mix.word32s[round % num_words]);
            const int64_t parent_index = t % num_cache_items;
            mix = fnv1_512(mix, le::uint32s(cache[parent_index]));
        }

        ALWAYS_INLINE hash512 final() noexcept { return keccak512(le::uint32s(mix)); }
    };

    // hash512 calculate_dataset_item_512(const epoch_context& context, uint32_t index) noexcept {
    //    item_state item{context, index};
    //    for (uint32_t i{0}; i < full_dataset_item_parents; ++i) {
    //        item.update(i);
    //    }
    //    return item.final();
    //}

    hash1024 calculate_dataset_item_1024(const epoch_context& context, uint32_t index) noexcept {
        item_state item0{context, index * 2};
        item_state item1{context, index * 2 + 1};

        for (uint32_t i{0}; i < full_dataset_item_parents; ++i) {
            item0.update(i);
            item1.update(i);
        }

        return hash1024{{item0.final(), item1.final()}};
    }

    void build_light_cache(hash_512_function hash_function, hash512 cache[], uint32_t num_items, const hash256& seed) {
        hash512 item{hash_function(seed.bytes, sizeof(seed))};
        cache[0] = item;
        for (uint32_t i{1}; i < num_items; i++) {
            item = hash_function(item.bytes, sizeof(item));
            cache[i] = item;
        }

        for (uint32_t round{0}; round < light_cache_rounds; round++) {
            for (uint32_t i{0}; i < num_items; i++) {
                // Fist index: 4 first bytes of the item as little-endian integer.
                const uint32_t t = le::uint32(cache[i].word32s[0]);
                const uint32_t v = t % num_items;

                // Second index.
                const uint32_t w = (num_items + (i - 1)) % num_items;
                const hash512 x{xor_512(cache[v], cache[w])};
                cache[i] = hash_function(x.bytes, sizeof(x));
            }
        }
    }

    hash512 hash_seed(const hash256& header, uint64_t nonce) noexcept {
        nonce = le::uint64(nonce);
        uint8_t init_data[sizeof(header) + sizeof(nonce)];
        std::memcpy(&init_data[0], &header, sizeof(header));
        std::memcpy(&init_data[sizeof(header)], &nonce, sizeof(nonce));
        return keccak512(init_data, sizeof(init_data));
    }

    hash256 hash_mix(const epoch_context& context, const hash512& seed) {
        static constexpr size_t num_words{sizeof(hash1024) / sizeof(uint32_t)};
        const uint32_t index_limit{context.full_dataset_num_items};
        const uint32_t seed_init{le::uint32(seed.word32s[0])};

        hash1024 mix{{le::uint32s(seed), le::uint32s(seed)}};

        for (uint32_t i = 0; i < num_dataset_accesses; ++i) {
            const uint32_t p = fnv1(i ^ seed_init, mix.word32s[i % num_words]) % index_limit;
            const hash1024 newdata = le::uint32s(calculate_dataset_item_1024(context, p));

            for (size_t j = 0; j < num_words; ++j) mix.word32s[j] = fnv1(mix.word32s[j], newdata.word32s[j]);
        }

        hash256 mix_hash;
        for (size_t i = 0; i < num_words; i += 4) {
            const uint32_t h1 = fnv1(mix.word32s[i], mix.word32s[i + 1]);
            const uint32_t h2 = fnv1(h1, mix.word32s[i + 2]);
            const uint32_t h3 = fnv1(h2, mix.word32s[i + 3]);
            mix_hash.word32s[i / 4] = h3;
        }

        return le::uint32s(mix_hash);
    }

    hash256 hash_final(const hash512& seed, const hash256& mix) noexcept {
        uint8_t final_data[sizeof(seed) + sizeof(mix)];
        std::memcpy(&final_data[0], seed.bytes, sizeof(seed));
        std::memcpy(&final_data[sizeof(seed)], mix.bytes, sizeof(mix));
        return keccak256(final_data, sizeof(final_data));
    }

    epoch_context* create_epoch_context(uint32_t epoch_number) noexcept {
        static constexpr size_t context_alloc_size{sizeof(epoch_context)};
        const uint32_t light_cache_num_items{calculate_light_cache_num_items(epoch_number)};
        const uint32_t full_dataset_num_items{calculate_full_dataset_num_items(epoch_number)};
        const size_t light_cache_size{static_cast<size_t>(light_cache_num_items) * light_cache_item_size};

        const size_t alloc_size{context_alloc_size + light_cache_size};

        // Allocate light_cache memory
        char* const alloc_data = static_cast<char*>(std::calloc(1, alloc_size));
        if (!alloc_data) {
            return nullptr;
        }

        // Build light cache
        hash512* const light_cache{reinterpret_cast<hash512*>(alloc_data + context_alloc_size)};
        const hash256 epoch_seed{calculate_seed_from_epoch(epoch_number)};
        build_light_cache(keccak512, light_cache, light_cache_num_items, epoch_seed);

        epoch_context* const context =
            new (alloc_data) epoch_context{epoch_number, light_cache_num_items, full_dataset_num_items, light_cache};
        return context;
    }

    void destroy_epoch_context(epoch_context* context) noexcept {
        context->~epoch_context();
        std::free(context);
    }

}  // namespace detail

/** Checks if the number is prime. Requires the number to be > 2 and odd. */
static bool is_unsigned_odd_prime(const uint32_t number) noexcept {
    if (!(number & 1)) {
        return false;
    }

    /* Check factors up to sqrt(number).
     *
     * To avoid computing sqrt, compare d*d <= number with
     * 64-bit precision.
     */
    for (unsigned long long d{3}; d * d <= (unsigned long long)number; d += 2) {
        if (number % d == 0) {
            return false;
        }
    }
    return true;
}

uint32_t find_largest_unsigned_prime(uint32_t upper_bound) noexcept {
    if (upper_bound < 2) {
        return 0;
    }

    /* If even number, skip it. */
    uint32_t n{(upper_bound & 1) ? upper_bound : upper_bound - 1};

    /* Test descending odd numbers. */
    while (!is_unsigned_odd_prime(n)) {
        n -= 2;
    }
    return n;
}

uint32_t calculate_light_cache_num_items(uint32_t epoch_number) noexcept {
    static constexpr uint32_t item_size = sizeof(hash512);
    static constexpr uint32_t num_items_init = light_cache_init_size / item_size;
    static constexpr uint32_t num_items_growth = light_cache_growth / item_size;
    static_assert(light_cache_init_size % item_size == 0, "light_cache_init_size not multiple of item size");
    static_assert(light_cache_growth % item_size == 0, "light_cache_growth not multiple of item size");

    uint32_t num_items_upper_bound = num_items_init + epoch_number * num_items_growth;
    uint32_t num_items = find_largest_unsigned_prime(num_items_upper_bound);
    return num_items;
}

uint32_t calculate_full_dataset_num_items(uint32_t epoch_number) noexcept {
    static constexpr uint32_t item_size = sizeof(hash1024);
    static constexpr uint32_t num_items_init = full_dataset_init_size / item_size;
    static constexpr uint32_t num_items_growth = full_dataset_growth / item_size;
    static_assert(full_dataset_init_size % item_size == 0, "full_dataset_init_size not multiple of item size");
    static_assert(full_dataset_growth % item_size == 0, "full_dataset_growth not multiple of item size");

    uint32_t num_items_upper_bound = num_items_init + epoch_number * num_items_growth;
    uint32_t num_items = find_largest_unsigned_prime(num_items_upper_bound);
    return num_items;
}

hash256 calculate_seed_from_epoch(uint32_t epoch_number) noexcept {
    hash256 seed{};
    for (uint32_t i{0}; i < epoch_number; ++i) {
        seed = keccak256(seed);
    }
    return seed;
}

std::optional<uint32_t> calculate_epoch_from_seed(const hash256& seed) noexcept {
    static constexpr uint32_t num_tries{30000};
    static std::optional<uint32_t> cached_epoch_number{};
    static hash256 cached_epoch_seed{};

    // Do we have something in cache ?
    if (cached_epoch_number.has_value()) {
        if (is_equal(seed, cached_epoch_seed)) {
            return cached_epoch_number.value();
        }
        // Try the next seed, will match for sequential epoch access.
        hash256 next{keccak256(cached_epoch_seed)};
        if (is_equal(next, seed)) {
            cached_epoch_seed = next;
            *cached_epoch_number = *cached_epoch_number + 1;
            return cached_epoch_number.value();
        }
    }

    // Nothing in cache or not next in sequence ...
    // restart linear search from epoch 0
    cached_epoch_seed = {};
    for (uint32_t i{0}; i < num_tries; i++) {
        if (is_equal(cached_epoch_seed, seed)) {
            cached_epoch_number.emplace(i);
            return cached_epoch_number.value();
        }
        cached_epoch_seed = keccak256(cached_epoch_seed);
    }

    // No matches found
    cached_epoch_number.reset();
    return std::nullopt;
}

result hash(const epoch_context& context, const hash256& header, uint64_t nonce) {
    const hash512 seed{detail::hash_seed(header, nonce)};
    const hash256 mix_hash{detail::hash_mix(context, seed)};
    return {detail::hash_final(seed, mix_hash), mix_hash};
}

bool verify_light(const hash256& header_hash, const hash256& mix_hash, uint64_t nonce,
                  const hash256& boundary) noexcept {
    const hash512 hash_seed{detail::hash_seed(header_hash, nonce)};
    const hash256 hash_final{detail::hash_final(hash_seed, mix_hash)};
    return is_less_or_equal(hash_final, boundary);
}

bool verify_full(const epoch_context& context, const hash256& header_hash, const hash256& mix_hash, uint64_t nonce,
                 const hash256& boundary) noexcept {

    const hash512 hash_seed{detail::hash_seed(header_hash, nonce)};
    const hash256 hash_final{detail::hash_final(hash_seed, mix_hash)};
    if (!is_less_or_equal(hash_final, boundary)) {
        return false;
    }
    const hash256 expected_mix_hash = detail::hash_mix(context, hash_seed);
    return is_equal(mix_hash, expected_mix_hash);
}

epoch_context_ptr create_epoch_context(uint32_t epoch_number) noexcept {
    return {detail::create_epoch_context(epoch_number), detail::destroy_epoch_context};
}

hash256 get_boundary_from_diff(const intx::uint256 difficulty) noexcept {

    static intx::uint256 dividend{
        intx::from_string<intx::uint256>("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")};

    hash256 ret{};

    if (difficulty > 1u) {
        auto result = dividend / difficulty;
        std::memcpy(ret.bytes, intx::as_bytes(result), 32);
    } else {
        std::memcpy(ret.bytes, intx::as_bytes(dividend), 32);
    }
    return ret;

}

}  // namespace ethash
