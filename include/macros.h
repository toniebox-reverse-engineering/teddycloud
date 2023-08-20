#ifndef __MACROS_H__
#define __MACROS_H__

// #define min(a, b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })
// #define max(a, b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })
#define coerce(val, min, max)   \
    do                          \
    {                           \
        if ((val) > (max))      \
        {                       \
            val = max;          \
        }                       \
        else if ((val) < (min)) \
        {                       \
            val = min;          \
        }                       \
    } while (0)
#define xstr(s) str(s)
#define str(s) #s

#endif
