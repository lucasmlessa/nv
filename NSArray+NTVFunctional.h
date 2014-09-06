//
//  NSArray+NVFunctional.h
//  Notation
//
//  Created by Zachary Waldowski on 8/23/14.
//  Copyright (c) 2014 elasticthreads. All rights reserved.
//

@import Foundation;

@interface NSArray (NTVFunctional)

+ (instancetype)ntv_arrayWithCount:(NSUInteger)count block:(id(^)(NSUInteger idx))block;

@end
