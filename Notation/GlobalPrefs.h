//
//  GlobalPrefs.h
//  Notation
//
//  Created by Zachary Schneirov on 1/31/06.

/*Copyright (c) 2010, Zachary Schneirov. All rights reserved.
    This file is part of Notational Velocity.

    Notational Velocity is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Notational Velocity is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Notational Velocity.  If not, see <http://www.gnu.org/licenses/>. */

#import "SynchronizedNoteProtocol.h"

extern NSString *NoteTitleColumnString;
extern NSString *NoteLabelsColumnString;
extern NSString *NoteDateModifiedColumnString;
extern NSString *NoteDateCreatedColumnString;
extern NSString *NotePreviewString;

extern NSString *NVPTFPboardType;

extern NSString *const NVAppActivationShortcutKey;

@class NotesTableView;
@class BookmarksController;
@class NotationPrefs;

enum {
	NoteTitleColumn, NoteLabelsColumn, NoteDateModifiedColumn, NoteDateCreatedColumn
};

#define ColumnIsSet(__ColumnEnum, __columnsBitmap) (((1 << (__ColumnEnum)) & (__columnsBitmap)) != 0)

@protocol GlobalPrefsResponder <NSObject>

- (void)settingChangedForSelectorString:(NSString *)selectorString;

@end

BOOL ColorsEqualWith8BitChannels(NSColor *c1, NSColor *c2);

@interface GlobalPrefs : NSObject {
	NSUserDefaults *defaults;

	NSMutableDictionary *selectorObservers;

	BookmarksController *bookmarksController;
	NotationPrefs *notationPrefs;
	NSDictionary *noteBodyAttributes, *searchTermHighlightAttributes;
	NSMutableParagraphStyle *noteBodyParagraphStyle;
	NSFont *noteBodyFont;
	BOOL autoCompleteSearches;

	NSMutableArray *tableColumns;
	unsigned int tableColsBitmap;
}

+ (GlobalPrefs *)defaultPrefs;

- (void)registerWithTarget:(id <GlobalPrefsResponder>)sender forChangesInSettings:(SEL)firstSEL, ...;

- (void)registerForSettingChange:(SEL)selector withTarget:(id <GlobalPrefsResponder>)sender;

- (void)unregisterForNotificationsFromSelector:(SEL)selector sender:(id <GlobalPrefsResponder>)sender;

- (void)notifyCallbacksForSelector:(SEL)selector excludingSender:(id <GlobalPrefsResponder>)sender;

- (void)setNotationPrefs:(NotationPrefs *)newNotationPrefs sender:(id)sender;

- (NotationPrefs *)notationPrefs;

- (void)removeTableColumn:(NSString *)columnKey sender:(id)sender;

- (void)addTableColumn:(NSString *)columnKey sender:(id)sender;

- (NSArray *)visibleTableColumns;

- (unsigned int)tableColumnsBitmap;

- (void)setSortedTableColumnKey:(NSString *)sortedKey reversed:(BOOL)reversed sender:(id)sender;

- (NSString *)sortedTableColumnKey;

- (BOOL)tableIsReverseSorted;

- (BOOL)tableColumnsShowPreview;

- (void)setTableColumnsShowPreview:(BOOL)showPreview sender:(id)sender;

- (void)resolveNoteBodyFontFromNotationPrefsFromSender:(id)sender;

- (void)setNoteBodyFont:(NSFont *)aFont sender:(id)sender;

- (void)_setNoteBodyFont:(NSFont *)aFont;

- (NSFont *)noteBodyFont;

- (NSDictionary *)noteBodyAttributes;

- (NSParagraphStyle *)noteBodyParagraphStyle;

- (BOOL)_bodyFontIsMonospace;

- (void)setForegroundTextColor:(NSColor *)aColor sender:(id)sender;

- (NSColor *)foregroundTextColor;

- (void)setBackgroundTextColor:(NSColor *)aColor sender:(id)sender;

- (NSColor *)backgroundTextColor;

- (void)setTabIndenting:(BOOL)value sender:(id)sender;

- (BOOL)tabKeyIndents;

- (void)setUseTextReplacement:(BOOL)value sender:(id)sender;

- (BOOL)useTextReplacement;

- (void)setCheckSpellingAsYouType:(BOOL)value sender:(id)sender;

- (BOOL)checkSpellingAsYouType;

- (void)setConfirmNoteDeletion:(BOOL)value sender:(id)sender;

- (BOOL)confirmNoteDeletion;

- (void)setQuitWhenClosingWindow:(BOOL)value sender:(id)sender;

- (BOOL)quitWhenClosingWindow;

- (void)registerAppActivationKeystrokeWithHandler:(void (^)(void))block;

- (void)setPastePreservesStyle:(BOOL)value sender:(id)sender;

- (BOOL)pastePreservesStyle;

- (void)setAutoFormatsDoneTag:(BOOL)value sender:(id)sender;

- (BOOL)autoFormatsDoneTag;

- (BOOL)autoIndentsNewLines;

- (void)setAutoIndentsNewLines:(BOOL)value sender:(id)sender;

- (BOOL)autoFormatsListBullets;

- (void)setAutoFormatsListBullets:(BOOL)value sender:(id)sender;

- (void)setLinksAutoSuggested:(BOOL)value sender:(id)sender;

- (BOOL)linksAutoSuggested;

- (void)setMakeURLsClickable:(BOOL)value sender:(id)sender;

- (BOOL)URLsAreClickable;

- (void)setShouldHighlightSearchTerms:(BOOL)shouldHighlight sender:(id)sender;

- (BOOL)highlightSearchTerms;

- (void)setSearchTermHighlightColor:(NSColor *)color sender:(id)sender;

- (NSDictionary *)searchTermHighlightAttributes;

- (NSColor *)searchTermHighlightColorRaw:(BOOL)isRaw;

- (void)setSoftTabs:(BOOL)value sender:(id)sender;

- (BOOL)softTabs;

- (NSInteger)numberOfSpacesInTab;

- (float)tableFontSize;

- (void)setTableFontSize:(float)fontSize sender:(id)sender;

- (void)setHorizontalLayout:(BOOL)value sender:(id)sender;

- (BOOL)horizontalLayout;

- (BOOL)autoCompleteSearches;

- (void)setAutoCompleteSearches:(BOOL)value sender:(id)sender;

- (NSString *)lastSelectedPreferencesPane;

- (void)setLastSelectedPreferencesPane:(NSString *)pane sender:(id)sender;

- (double)scrollOffsetOfLastSelectedNote;

- (CFUUIDBytes)UUIDBytesOfLastSelectedNote;

- (NSString *)lastSearchString;

- (void)setLastSearchString:(NSString *)string selectedNote:(id <SynchronizedNote>)aNote scrollOffsetForTableView:(NotesTableView *)tv sender:(id)sender;

- (void)saveCurrentBookmarksFromSender:(id)sender;

- (BookmarksController *)bookmarksController;

- (void)setBookmarkDataForDefaultDirectory:(NSData *)bookmark sender:(id)sender;

- (NSData *)bookmarkDataForDefaultDirectory;

- (NSString *)displayNameForDefaultDirectoryReturningURL:(out NSURL **)outURL;

- (void)setBlorImportAttempted:(BOOL)value;

- (BOOL)triedToImportBlor;

- (void)synchronize;

- (NSImage *)iconForDefaultDirectoryReturningURL:(out NSURL **)outURL;

//
- (void)setRTL:(BOOL)value sender:(id)sender;

- (BOOL)rtl;

- (BOOL)showWordCount;

- (void)setShowWordCount:(BOOL)value;

- (void)setUseMarkdownImport:(BOOL)value sender:(id)sender;

- (BOOL)useMarkdownImport;

- (void)setUseReadability:(BOOL)value sender:(id)sender;

- (BOOL)useReadability;

- (void)setShowGrid:(BOOL)value sender:(id)sender;

- (BOOL)showGrid;

- (void)setAlternatingRows:(BOOL)value sender:(id)sender;

- (BOOL)alternatingRows;

- (void)setUseAutoPairing:(BOOL)value;

- (BOOL)useAutoPairing;

- (void)setMaxNoteBodyWidth:(CGFloat)maxWidth sender:(id)sender;

- (void)setManagesTextWidthInWindow:(BOOL)manageIt sender:(id)sender;

- (BOOL)managesTextWidthInWindow;

- (CGFloat)maxNoteBodyWidth;
@end