#ifndef __THREADS_FIXED_POINT_H
#define __THREADS_FIXED_POINT_H

#include <stdint.h>

#define FIXED_POINT_P 17

#define FIXED_POINT_Q 14

#define FIXED_POINT_F (1 << FIXED_POINT_Q)

#define CONVERT_INT_TO_FIXED_POINT(N) (N * FIXED_POINT_F)

#define FIXED_POINT_TO_INT_ROUND_TO_ZERO(X) (X / FIXED_POINT_F)

#define FIXED_POINT_TO_INT_ROUND_TO_NEAREST(X) \
		(X >= 0 ? ((X + (FIXED_POINT_F / 2)) / FIXED_POINT_F)  \
			    : ((X - (FIXED_POINT_F / 2)) / FIXED_POINT_F))

#define FIXED_POINT_ADD_FIXED_POINT(X, Y) (X + Y)

#define FIXED_POINT_SUB_FIXED_POINT(X, Y) (X - Y)

#define FIXED_POINT_ADD_INT(X, N) (X + (N * FIXED_POINT_F))

#define FIXED_POINT_SUB_INT(X, N) (X - (N * FIXED_POINT_F))

#define FIXED_POINT_MUL_FIXED_POINT(X, N) ((((int64_t) X) * N) / FIXED_POINT_F)

#define FIXED_POINT_MUL_INT(X, N) (X * N)

#define FIXED_POINT_DIV_FIXED_POINT(X, N) ((((int64_t) X) * FIXED_POINT_F) / N)

#define FIXED_POINT_DIV_INT(X, N) (X / N)

#endif /* threads/fixed-point.h */