//
//  ETScrollView.m
//  Notation
//
//  Created by elasticthreads on 3/14/11.
//

#import <Foundation/Foundation.h>
#import "GlobalPrefs.h"

@interface ETScrollView : NSScrollView <GlobalPrefsObserver> {
    Class scrollerClass;
    BOOL needsOverlayTiling;
}

- (void)changeUseETScrollbarsOnLion;

@end
