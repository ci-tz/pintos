#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#include <stdint.h>

typedef int32_t fixed_point_t;

static const fixed_point_t f = 1 << 14;

// Convert n to fixed point
static inline fixed_point_t i2f(int n)
{
    return n * f;
}

// Convert x to integer (rounding toward zero)
static inline int f2i_zero(fixed_point_t x)
{
    return x / f;
}

// Convert x to integer (rounding to nearest)
static inline int f2i_near(fixed_point_t x)
{
    if (x >= 0)
        return (x + f / 2) / f;
    else
        return (x - f / 2) / f;
}

// Add x and y
static inline fixed_point_t add_ff(fixed_point_t x, fixed_point_t y)
{
    return x + y;
}

// Subtract y from x
static inline fixed_point_t sub_ff(fixed_point_t x, fixed_point_t y)
{
    return x - y;
}

// Add x and n
static inline fixed_point_t add_fi(fixed_point_t x, int n)
{
    return x + n * f;
}

// Subtract n from x
static inline fixed_point_t sub_fi(fixed_point_t x, int n)
{
    return x - n * f;
}

// Multiply x by y
static inline fixed_point_t multi_ff(fixed_point_t x, fixed_point_t y)
{
    return ((int64_t)x) * y / f;
}

// Multiply x by n
static inline fixed_point_t multi_fi(fixed_point_t x, int n)
{
    return x * n;
}

// Divide x by y
static inline fixed_point_t div_ff(fixed_point_t x, fixed_point_t y)
{
    return ((int64_t)x) * f / y;
}

// Divide x by n
static inline fixed_point_t div_fi(fixed_point_t x, int n)
{
    return x / n;
}

#endif