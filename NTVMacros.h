//
//  NTVMacros.h
//  Notation
//
//  Created by Zachary Waldowski on 8/23/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

#ifndef NTV_MACROS
#define NTV_MACROS

#import <Foundation/Foundation.h>

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

#endif /* !NTV_MACROS */
