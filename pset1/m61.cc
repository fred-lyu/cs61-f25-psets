#include "m61.hh"
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <sys/mman.h>
#include <map>
#include <unordered_map>
#include <unordered_set>

constexpr char CANARY = 0xAB;
constexpr size_t CANARY_SIZE = sizeof(CANARY);
struct m61_memory_meta {
    char file[16];
    int line;
};
constexpr size_t META_SIZE = sizeof(m61_memory_meta) + CANARY_SIZE;

constexpr size_t max_align = alignof(std::max_align_t);
#define ROUND_UP(pos) ((pos + max_align - 1) / max_align * max_align)


struct m61_memory_buffer {
    char* buffer;
    // size_t pos = 0;
    bool inited = false;
    size_t size = 8 << 20; /* 8 MiB */

    m61_memory_buffer();
    ~m61_memory_buffer();
};

static m61_memory_buffer default_buffer;


m61_memory_buffer::m61_memory_buffer() {
    void* buf = mmap(nullptr,    // Place the buffer at a random address
        this->size,              // Buffer should be 8 MiB big
        PROT_WRITE,              // We want to read and write the buffer
        MAP_ANON | MAP_PRIVATE, -1, 0);
                                 // We want memory freshly allocated by the OS
    assert(buf != MAP_FAILED);
    this->buffer = (char*) buf;
}

m61_memory_buffer::~m61_memory_buffer() {
    munmap(this->buffer, this->size);
}


static m61_statistics stats = {};
static std::map<uintptr_t, size_t> map_alloced_size;
static std::unordered_set<uintptr_t> unset_freed;
static std::map<uintptr_t, size_t> map_freed_size;


static void m61_stats_alloc(void* ptr, size_t sz, const char* file, int line)
{
    if (ptr)
    {
        stats.nactive += 1;
        stats.ntotal += 1;
        stats.active_size += sz;
        stats.total_size += sz;
        map_alloced_size.insert({(uintptr_t)ptr, sz + META_SIZE});
        ((char*)ptr)[sz - 1 + CANARY_SIZE] = CANARY;
        m61_memory_meta* meta = reinterpret_cast<m61_memory_meta*>((char*)ptr + sz + CANARY_SIZE);
        strncpy(meta->file, file, sizeof(meta->file));
        meta->file[sizeof(meta->file) - 1] = '\0';
        meta->line = line;
    }
    else
    {
        stats.nfail += 1;
        stats.fail_size += sz;
    }
}


static void* m61_find_free_space(size_t sz) {
    // do we have a freed allocation that will work?
    for (auto& freed : map_freed_size) {
        size_t aligned_size = freed.second;
        if (aligned_size >= sz) {
            void* ptr = (void*)freed.first;
            size_t aligned_sz = ROUND_UP(sz);
            if (aligned_size > aligned_sz)
            {
                // 说明还有剩余对齐内存，需要保留
                map_freed_size.insert({freed.first + aligned_sz, aligned_size - aligned_sz});
            }
            map_freed_size.erase(freed.first);

            return ptr;
        }
    }
    // otherwise fail
    return nullptr;
}


/// m61_malloc(sz, file, line)
///    Returns a pointer to `sz` bytes of freshly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    return either `nullptr` or a pointer to a unique allocation.
///    The allocation request was made at source code location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, int line) {
    // Your code here.
    void* ptr = nullptr;
    if (sz == 0)
    {
        return ptr;
    }

    if (!default_buffer.inited)
    {
        map_alloced_size.clear();
        map_freed_size.clear();
        map_freed_size.insert({(uintptr_t)default_buffer.buffer, default_buffer.size});
        default_buffer.inited = true;
    }

    if (sz <= SIZE_MAX - META_SIZE)
    {
        ptr = m61_find_free_space(sz + META_SIZE);
    }

    m61_stats_alloc(ptr, sz, file, line);

    return ptr;
}

static void m61_try_merge_mem(uintptr_t ptr, size_t aligned_size)
{
    auto [new_it, inserted] = map_freed_size.insert({ptr, aligned_size});
    assert(inserted);

    // 向后合并
    auto it = std::next(new_it);
    if (it != map_freed_size.end())
    {
        if (ptr + aligned_size == it->first)
        {
            new_it->second += it->second;
            map_freed_size.erase(it);
        }
    }

    // 向前合并
    if (new_it != map_freed_size.begin())
    {
        it = std::prev(new_it);
        if (it->first + it->second == ptr)
        {
            it->second += new_it->second;
            map_freed_size.erase(new_it);
        }
    }
}

/// m61_free(ptr, file, line)
///    Frees the memory allocation pointed to by `ptr`. If `ptr == nullptr`,
///    does nothing. Otherwise, `ptr` must point to a currently active
///    allocation returned by `m61_malloc`. The free was called at location
///    `file`:`line`.

void m61_free(void* ptr, const char* file, int line) {
    if (!ptr)
    {
        return;
    }

    if ((uintptr_t)ptr < m61_get_statistics().heap_min || (uintptr_t)ptr >= m61_get_statistics().heap_max)
    {
        fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not in heap\n", file, line, ptr);
        abort();
    }

    // Your code here. The handout code does nothing!
    auto it = map_alloced_size.find((uintptr_t)ptr);
    if (it != map_alloced_size.end())
    {
        size_t sz = it->second - META_SIZE;
        stats.nactive -= 1;
        stats.active_size -= sz;

        // 合并小块内存
        m61_try_merge_mem(it->first, ROUND_UP(it->second));

        // 检测是否有超出内存边界的写入
        if (((char*)ptr)[sz] != CANARY)
        {
            fprintf(stderr, "MEMORY BUG: %s:%d: detected wild write during free of pointer %p\n", file, line, ptr);
            abort();
        }

        // 删除活跃内存记录
        map_alloced_size.erase(it);

        // 记录删除记录
        unset_freed.insert((uintptr_t)ptr);
    }
    else
    {
        if (unset_freed.count((uintptr_t)ptr))
        {
            fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, double free\n", file, line, ptr);
        }
        else
        {
            fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n", file, line, ptr);
            if (!map_alloced_size.empty())
            {
                auto it_lower_bound = map_alloced_size.lower_bound((uintptr_t)ptr);
                if (it_lower_bound != map_alloced_size.begin()){
                    it_lower_bound = std::prev(it_lower_bound);

                    if (it_lower_bound->first + it_lower_bound->second >= (uintptr_t)ptr)
                    {
                        m61_memory_meta* meta = reinterpret_cast<m61_memory_meta*>((char*)it_lower_bound->first + it_lower_bound->second - META_SIZE + CANARY_SIZE);
                        fprintf(stderr, "  %s:%d: %p is %lu bytes inside a %lu byte region allocated here\n", meta->file, meta->line, ptr, (uintptr_t)ptr - it_lower_bound->first, it_lower_bound->second - META_SIZE);
                    }
                }
            }
        }

        abort();
    }
}


/// m61_calloc(count, sz, file, line)
///    Returns a pointer a fresh dynamic memory allocation big enough to
///    hold an array of `count` elements of `sz` bytes each. Returned
///    memory is initialized to zero. The allocation request was at
///    location `file`:`line`. Returns `nullptr` if out of memory; may
///    also return `nullptr` if `count == 0` or `size == 0`.

void* m61_calloc(size_t count, size_t sz, const char* file, int line) {
    // Your code here (not needed for first tests).
    if (count == 0 || sz == 0)
    {
        return nullptr;
    }

    if ((size_t) -1 / sz < count || (size_t) -1 / count < sz)
    {
        m61_stats_alloc(nullptr, count * sz, file, line);
        return nullptr;
    }

    void* ptr = m61_malloc(count * sz, file, line);
    if (ptr) {
        memset(ptr, 0, count * sz);
    }
    return ptr;
}


/// m61_get_statistics()
///    Return the current memory statistics.

m61_statistics m61_get_statistics() {
    // Your code here.
    // The handout code sets all statistics to enormous numbers.
    if (stats.heap_min == 0)
    {
        stats.heap_min = (uintptr_t)default_buffer.buffer;
        stats.heap_max = (uintptr_t)default_buffer.buffer + default_buffer.size;
    }
    return stats;
}


/// m61_print_statistics()
///    Prints the current memory statistics.

void m61_print_statistics() {
    m61_statistics local_stats = m61_get_statistics();
    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           local_stats.nactive, local_stats.ntotal, local_stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           local_stats.active_size, local_stats.total_size, local_stats.fail_size);
}


/// m61_print_leak_report()
///    Prints a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_print_leak_report() {
    // Your code here.
    for (auto& alloced : map_alloced_size)
    {
        size_t sz = alloced.second - META_SIZE;
        m61_memory_meta* meta = reinterpret_cast<m61_memory_meta*>((char*)alloced.first + sz + CANARY_SIZE);
        printf("LEAK CHECK: %s:%d: allocated object %p with size %lu\n", meta->file, meta->line, (void*)alloced.first, sz);
    }
}
