//
//  NTVLinkingEditorScrollView.h
//  Notation
//
//  Created by Zachary Waldowski on 9/7/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

#import "ETScrollView.h"
#import "GlobalPrefs.h"

@class LinkingEditor;

@interface NTVLinkingEditorScrollView : ETScrollView <GlobalPrefsObserver>

@property (assign) LinkingEditor *documentView;

@end
