//
//  NTVMath.h
//  Notation
//
//  Created by Zachary Waldowski on 8/23/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

#import <math.h>
#import <tgmath.h>
#import <CoreGraphics/CGBase.h>
#import "NTVMacros.h"

#ifndef __cplusplus

#ifndef NTV_TG_MATH
#define NTV_TG_MATH

#define roundf(__x)     __tg_round(__tg_promote1((__x))(__x))
#define floorf(__x)     __tg_floor(__tg_promote1((__x))(__x))
#define ceilf(__x)      __tg_ceil(__tg_promote1((__x))(__x))
#define fmaxf(__x, __y) __tg_fmax(__tg_promote2((__x), (__y))(__x), __tg_promote2((__x), (__y))(__y))
#define fminf(__x, __y) __tg_fmin(__tg_promote2((__x), (__y))(__x), __tg_promote2((__x), (__y))(__y))
#define expf(__x)       __tg_exp(__tg_promote1((__x))(__x))
#define sqrtf(__x)      __tg_sqrt(__tg_promote1((__x))(__x))
#define logf(__x)       __tg_log(__tg_promote1((__x))(__x))
#define fabsf(__x)      __tg_fabs(__tg_promote1((__x))(__x))
#define powf(__x, __y)  __tg_pow(__tg_promote2((__x), (__y))(__x), __tg_promote2((__x), (__y))(__y))
#define cosf(__x)       __tg_cos(__tg_promote1((__x))(__x))
#define sinf(__x)       __tg_sin(__tg_promote1((__x))(__x))
#define tanf(__x)       __tg_tan(__tg_promote1((__x))(__x))

#endif /* NTV_TG_MATH */

#endif /* !defined (__cplusplus) */

#ifndef NTV_MATH
#define NTV_MATH

NTV_ALWAYS_INLINE CGFloat rroundf(CGFloat pt, CGFloat scale){
	return (scale > 0) ? (__tg_round(pt * scale) / scale) : __tg_round(pt);
}
NTV_ALWAYS_INLINE CGFloat rceilf(CGFloat pt, CGFloat scale){
	return (scale > 0) ? (__tg_ceil(pt * scale) / scale) : __tg_ceil(pt);
}
NTV_ALWAYS_INLINE CGFloat rfloorf(CGFloat pt, CGFloat scale){
	return (scale > 0) ? (__tg_floor(pt * scale) / scale) : __tg_floor(pt);
}

#endif /* NTV_MATH */
