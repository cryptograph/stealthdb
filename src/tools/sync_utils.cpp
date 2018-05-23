#include "tools/sync_utils.hpp"

void spin_lock(int volatile* p)
{
    while (!__sync_bool_compare_and_swap(p, 0, 1))
    {
        while (*p)
            __asm__("pause");
    }
}

void spin_unlock(int volatile* p)
{
    asm volatile(""); // acts as a memory barrier.
    *p = 0;
}

void spin_lock(unsigned char volatile* p)
{
    while (!__sync_bool_compare_and_swap(p, 0, 1))
    {
        while (*p)
            __asm__("pause");
    }
}

void spin_unlock(unsigned char volatile* p)
{
    asm volatile(""); // acts as a memory barrier.
    *p = 0;
}
