//
//  NTVMacros.h
//  Notation
//
//  Created by Zachary Waldowski on 8/23/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

#ifndef NTV_MACROS
#define NTV_MACROS

@class AppController;

#if !defined(NTV_ALWAYS_INLINE)
    #if defined(__GNUC__)
        #define NTV_ALWAYS_INLINE static __inline__ __attribute__((always_inline))
    #elif defined(__MWERKS__) || defined(__cplusplus)
        #define NTV_ALWAYS_INLINE static inline
    #elif defined(_MSC_VER)
        #define NTV_ALWAYS_INLINE static __inline
    #elif TARGET_OS_WIN32
        #define NTV_ALWAYS_INLINE static __inline__
    #endif
#endif

NTV_ALWAYS_INLINE AppController *NTVAppDelegate(void) {
	return (AppController *)[NSApp delegate];
}

NTV_ALWAYS_INLINE BOOL NTVFloatsEqual(CGFloat a, CGFloat b) {
#if CGFLOAT_IS_DOUBLE
    return fabs(a - b) < DBL_EPSILON;
#else
    return fabsf(a - b) < FLT_EPSILON;
#endif
}

NTV_ALWAYS_INLINE NSComparator NTVReverseComparator(NSComparator ctor) {
    if (!ctor) { return NULL; };
    return [[^(id one, id two){
        NSComparisonResult result = ctor(one, two);
        if (result == NSOrderedAscending) {
            return NSOrderedDescending;
        } else if (result == NSOrderedDescending) {
            return NSOrderedAscending;
        }
        return NSOrderedSame;
    } copy] autorelease ];
}

#if !defined(NTVCompare)
#define __NTVCompare__(A,B,L) ({ \
    __typeof__(A) __NSX_PASTE__(__a,L) = (A); \
    __typeof__(B) __NSX_PASTE__(__b,L) = (B); \
    ((__NSX_PASTE__(__a,L) < __NSX_PASTE__(__b,L)) ? NSOrderedAscending : \
    ((__NSX_PASTE__(__a,L) > __NSX_PASTE__(__b,L)) ? NSOrderedDescending : \
    NSOrderedSame)); })
#define NTVCompare(A,B) __NTVCompare__(A,B,__COUNTER__)
#endif

#endif /* !NTV_MACROS */
