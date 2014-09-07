//
//  NTVLinkingEditorScrollView.m
//  Notation
//
//  Created by Zachary Waldowski on 9/7/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

#import "NTVLinkingEditorScrollView.h"
#import "LinkingEditor.h"
#import "AppController.h"

@implementation NTVLinkingEditorScrollView

@dynamic documentView;

- (NSView *)hitTest:(NSPoint)aPoint{
    NSRect vsRect=[[self verticalScroller] frame];
    vsRect.origin.x-=4.0;
    vsRect.size.width+=4.0;
    
    if (NSPointInRect (aPoint,vsRect)) {
        return [self verticalScroller];
    } else if([[self subviews]containsObject:[self findBarView]]) {
        NSView *tView=[super hitTest:aPoint];
        if ((tView==[self findBarView])||([tView superview]==[self findBarView])||([[tView className]isEqualToString:@"NSFindPatternFieldEditor"])) {
            [[self window]invalidateCursorRectsForView:tView];
            [[self documentView]setMouseInside:NO];
            return tView;
        }
    }
    [[self documentView]setMouseInside:YES];
    return [self documentView];
}

- (void)awakeFromNib{
    [super awakeFromNib];
    
    [GlobalPrefs.defaultPrefs registerTarget:self forChangesInSettings:
     @selector(setCheckSpellingAsYouType:sender:),
     @selector(setUseTextReplacement:sender:),
     @selector(setNoteBodyFont:sender:),
     @selector(setMakeURLsClickable:sender:),
     @selector(setSearchTermHighlightColor:sender:),
     @selector(setShouldHighlightSearchTerms:sender:), nil];
}

- (void)settingChangedForSelector:(SEL)selector {
    if (sel_isEqual(selector, @selector(setCheckSpellingAsYouType:sender:))) {
        [self.documentView setContinuousSpellCheckingEnabled:[GlobalPrefs.defaultPrefs checkSpellingAsYouType]];
    } else if (sel_isEqual(selector, @selector(setUseTextReplacement:sender:))) {
        [self.documentView setAutomaticTextReplacementEnabled:[GlobalPrefs.defaultPrefs useTextReplacement]];
    } else if (sel_isEqual(selector, @selector(setNoteBodyFont:sender:))) {
        [self.documentView setTypingAttributes:[GlobalPrefs.defaultPrefs noteBodyAttributes]];
    } else if (sel_isEqual(selector, @selector(setMakeURLsClickable:sender:))) {
        [self.documentView setLinkTextAttributes:[self.documentView preferredLinkAttributes]];
    } else if (sel_isEqual(selector, @selector(setSearchTermHighlightColor:sender:)) ||
               sel_isEqual(selector, @selector(setShouldHighlightSearchTerms:sender:))) {
        if (![GlobalPrefs.defaultPrefs highlightSearchTerms]) {
            [self.documentView removeHighlightedTerms];
        } else {
            NSString *typedString = [NTVAppDelegate() typedString];
            if (typedString)
                [self.documentView highlightTermsTemporarilyReturningFirstRange:typedString avoidHighlight:NO];
        }
    }
    
    [super settingChangedForSelector:selector];
}

@end
