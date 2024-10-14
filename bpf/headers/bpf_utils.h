#ifndef static_always_inline
#define static_always_inline static inline __attribute__((__always_inline__))
#endif

#define __BPF_MAP_DEF(_kt, _vt, _ents) \
    __type(key, _kt);                  \
    __type(value, _vt);                \
    __uint(max_entries, _ents);

#define MAP_HASH(name, key_type, value_type, max_entries)                                             \
    struct                                                                                            \
    {                                                                                                 \
        __uint(type, BPF_MAP_TYPE_HASH);                                                              \
        __BPF_MAP_DEF(key_type, value_type, max_entries)                                              \
    } __##name SEC(".maps");                                                                          \
                                                                                                      \
    static_always_inline __attribute__((unused)) value_type *name##__lookup(key_type *key)            \
    {                                                                                                 \
        return (value_type *)bpf_map_lookup_elem(&__##name, (const void *)key);                       \
    }                                                                                                 \
                                                                                                      \
    static_always_inline __attribute__((unused)) int name##__update(key_type *key, value_type *value) \
    {                                                                                                 \
        return bpf_map_update_elem(&__##name, (const void *)key, (const void *)value, BPF_ANY);       \
    }                                                                                                 \
                                                                                                      \
    static_always_inline __attribute__((unused)) int name##__delete(key_type *key)                    \
    {                                                                                                 \
        return bpf_map_delete_elem(&__##name, (const void *)key);                                     \
    }

#define BPF_HASH3(_name, _key_type, _leaf_type) \
    MAP_HASH(_name, _key_type, _leaf_type, 40960)

#define BPF_HASH4(_name, _key_type, _leaf_type, _size) \
    MAP_HASH(_name, _key_type, _leaf_type, _size)

// helper for default-variable macro function
#define BPF_HASHX(_1, _2, _3, _4, NAME, ...) NAME

#define BPF_HASH(...)                            \
    BPF_HASHX(__VA_ARGS__, BPF_HASH4, BPF_HASH3) \
    (__VA_ARGS__)