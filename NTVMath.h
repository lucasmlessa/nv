//
//  NTVMath.h
//  Notation
//
//  Created by Zachary Waldowski on 8/23/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

#import "NTVMacros.h"

#ifndef __cplusplus

#ifndef NTV_TG_MATH
#define NTV_TG_MATH

@import Darwin.C.complex;
@import Darwin.C.math;

#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || __has_extension(c_generic_selections)
# define __tg_generic(x, cfnl, cfn, cfnf, fnl, fn, fnf) \
	_Generic(x,                     \
		long double _Complex: cfnl, \
		double _Complex: cfn,       \
		float _Complex: cfnf,       \
		long double: fnl,           \
		default: fn,                \
		float: fnf                  \
	)
# define __tg_type(x) \
	__tg_generic(x, 0, 0, 0, 0, 0, 0)
# define __tg_impl_simple(x, y, z, fnl, fn, fnf, ...) \
	__tg_generic(__tg_type(x) + __tg_type(y) + __tg_type(z), fnl, fn, fnf, fnl, fn, fnf)(__VA_ARGS__)
# define __tg_impl_full(x, y, cfnl, cfn, cfnf, fnl, fn, fnf, ...) \
	__tg_generic(__tg_type(x) + __tg_type(y), cfnl, cfn, cfnf, fnl, fn, fnf)(__VA_ARGS__)
#else
# error "Not implemented for this compiler"
#endif

#define	__tg_full(x, fn) \
	__tg_impl_full(x, x, c##fn##l, c##fn, c##fn##f, fn##l, fn, fn##f, x)

#define	acos(x)     __tg_full(x, acos)
#define	asin(x)     __tg_full(x, asin)
#define	atan(x)     __tg_full(x, atan)
#define	acosh(x)    __tg_full(x, acosh)
#define	asinh(x)    __tg_full(x, asinh)
#define	atanh(x)    __tg_full(x, atanh)
#define	cos(x)      __tg_full(x, cos)
#define	sin(x)      __tg_full(x, sin)
#define	tan(x)      __tg_full(x, tan)
#define	cosh(x)     __tg_full(x, cosh)
#define	sinh(x)     __tg_full(x, sinh)
#define	tanh(x)     __tg_full(x, tanh)

#define	exp(x)      __tg_full(x, exp)
#define	log(x)      __tg_full(x, log)
#define	sqrt(x)     __tg_full(x, sqrt)
#define	pow(x, y)   __tg_impl_full(x, y, cpowl, cpow, cpowf, powl, pow, powf, x, y)
#define	fabs(x)     __tg_impl_full(x, x, cabsl, cabs, cabsf, fabsl, fabs, fabsf, x)

#define	__tg_simple(x, fn) \
	__tg_impl_simple(x, x, x, fn##l, fn, fn##f, x)

#define	round(x)    __tg_simple(x, round)
#define	lround(x)   __tg_simple(x, lround)
#define	rint(x)		__tg_simple(x, rint)
#define	floor(x)    __tg_simple(x, floor)
#define	ceil(x)     __tg_simple(x, ceil)
#define	fmax(x, y)  __tg_impl_simple(x, x, y, fmaxl, fmax, fmaxf, x, y)
#define	fmin(x, y)  __tg_impl_simple(x, x, y, fminl, fmin, fminf, x, y)

#endif /* NTV_TG_MATH */

#endif /* !defined (__cplusplus) */

#ifndef NTV_MATH
#define NTV_MATH

@import CoreGraphics.CGBase;

NTV_ALWAYS_INLINE CGFloat rroundf(CGFloat pt, CGFloat scale){
	return (scale > 0) ? (round(pt * scale) / scale) : round(pt);
}
NTV_ALWAYS_INLINE CGFloat rceilf(CGFloat pt, CGFloat scale){
	return (scale > 0) ? (ceil(pt * scale) / scale) : ceil(pt);
}
NTV_ALWAYS_INLINE CGFloat rfloorf(CGFloat pt, CGFloat scale){
	return (scale > 0) ? (floor(pt * scale) / scale) : floor(pt);
}

#endif /* NTV_MATH */
