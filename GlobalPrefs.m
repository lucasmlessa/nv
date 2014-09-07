//
//  GlobalPrefs.m
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


#import "GlobalPrefs.h"
#import "NSData_transformations.h"
#import "NotationPrefs.h"
#import "BookmarksController.h"
#import "AttributedPlainText.h"
#import "FastListDataSource.h"
#import "NotesTableView.h"
#import "PTHotKey.h"
#import "PTKeyCombo.h"
#import "PTHotKeyCenter.h"
#import "NSString_NV.h"
#import "AppController.h"
#import "BufferUtils.h"
#import "CFUUID+NTVAdditions.h"

static NSString *TriedToImportBlorKey = @"TriedToImportBlor";
static NSString *DirectoryAliasKey = @"DirectoryAlias";
static NSString *AutoCompleteSearchesKey = @"AutoCompleteSearches";
static NSString *NoteAttributesVisibleKey = @"NoteAttributesVisible";
static NSString *TableFontSizeKey = @"TableFontPointSize";
static NSString *TableSortColumnKey = @"TableSortColumn";
static NSString *TableIsReverseSortedKey = @"TableIsReverseSorted";
static NSString *TableColumnsHaveBodyPreviewKey = @"TableColumnsHaveBodyPreview";
static NSString *NoteBodyFontKey = @"NoteBodyFont";
static NSString *ConfirmNoteDeletionKey = @"ConfirmNoteDeletion";
static NSString *CheckSpellingInNoteBodyKey = @"CheckSpellingInNoteBody";
static NSString *TextReplacementInNoteBodyKey = @"TextReplacementInNoteBody";
static NSString *QuitWhenClosingMainWindowKey = @"QuitWhenClosingMainWindow";
static NSString *TabKeyIndentsKey = @"TabKeyIndents";
static NSString *PastePreservesStyleKey = @"PastePreservesStyle";
static NSString *AutoFormatsDoneTagKey = @"AutoFormatsDoneTag";
static NSString *AutoFormatsListBulletsKey = @"AutoFormatsListBullets";
static NSString *AutoSuggestLinksKey = @"AutoSuggestLinks";
static NSString *AutoIndentsNewLinesKey = @"AutoIndentsNewLines";
static NSString *HighlightSearchTermsKey = @"HighlightSearchTerms";
static NSString *SearchTermHighlightColorKey = @"SearchTermHighlightColor";
static NSString *ForegroundTextColorKey = @"ForegroundTextColor";
static NSString *BackgroundTextColorKey = @"BackgroundTextColor";
static NSString *UseSoftTabsKey = @"UseSoftTabs";
static NSString *NumberOfSpacesInTabKey = @"NumberOfSpacesInTab";
static NSString *MakeURLsClickableKey = @"MakeURLsClickable";
static NSString *AppActivationKeyCodeKey = @"AppActivationKeyCode";
static NSString *AppActivationModifiersKey = @"AppActivationModifiers";
static NSString *HorizontalLayoutKey = @"HorizontalLayout";
static NSString *BookmarksKey = @"Bookmarks";
static NSString *LastScrollOffsetKey = @"LastScrollOffset";
static NSString *LastSearchStringKey = @"LastSearchString";
static NSString *LastSelectedNoteUUIDBytesKey = @"LastSelectedNoteUUIDBytes";
static NSString *LastSelectedPreferencesPaneKey = @"LastSelectedPrefsPane";
//elasticthreads prefs
static NSString *StatusBarItem = @"StatusBarItem";
static NSString	*ShowDockIcon = @"ShowDockIcon";
static NSString	*KeepsMaxTextWidth = @"KeepsMaxTextWidth";
static NSString	*NoteBodyMaxWidth = @"NoteBodyMaxWidth";
static NSString	*ColorScheme = @"ColorScheme";
static NSString *UseMarkdownImportKey = @"UseMarkdownImport";
static NSString *UseReadabilityKey = @"UseReadability";
static NSString *ShowGridKey = @"ShowGrid";
static NSString *AlternatingRowsKey = @"AlternatingRows";
static NSString *RTLKey = @"rtl";
static NSString *ShowWordCount = @"ShowWordCount";
static NSString *markupPreviewMode = @"markupPreviewMode";
static NSString *UseAutoPairing = @"UseAutoPairing";
static NSString *UseETScrollbarsOnLion = @"UseETScrollbarsOnLion";
static NSString *UsesMarkdownCompletions = @"UsesMarkdownCompletions";
static NSString *UseFinderTagsKey = @"UseFinderTags";
//static NSString *PasteClipboardOnNewNoteKey = @"PasteClipboardOnNewNote";

//these 4 strings manually localized
NSString *NoteTitleColumnString = @"Title";
NSString *NoteLabelsColumnString = @"Tags";
NSString *NoteDateModifiedColumnString = @"Date Modified";
NSString *NoteDateCreatedColumnString = @"Date Added";

//virtual column
NSString *NotePreviewString = @"Note Preview";

NSString *NVPTFPboardType = @"Notational Velocity Poor Text Format";

NSString *HotKeyAppToFrontName = @"bring Notational Velocity to the foreground";


@implementation GlobalPrefs

- (id)init {
	self = [super init];
	if (!self) { return nil; }

	selectorObservers = [[NSMutableDictionary alloc] init];

	defaults = [NSUserDefaults standardUserDefaults];
	
	tableColumns = nil;
	
	[defaults registerDefaults:@{
		UseFinderTagsKey: @(IsMavericksOrLater),
		AutoSuggestLinksKey: @YES,
		AutoFormatsDoneTagKey: @YES, 
		AutoIndentsNewLinesKey: @YES, 
		AutoFormatsListBulletsKey: @YES,
		UseSoftTabsKey: @NO,
		NumberOfSpacesInTabKey: @4,
		PastePreservesStyleKey: @YES,
		TabKeyIndentsKey: @YES,
		ConfirmNoteDeletionKey: @YES,
		CheckSpellingInNoteBodyKey: @YES, 
		TextReplacementInNoteBodyKey: @NO, 
		AutoCompleteSearchesKey: @YES, 
		QuitWhenClosingMainWindowKey: @YES, 
		TriedToImportBlorKey: @NO,
		HorizontalLayoutKey: @NO,
		MakeURLsClickableKey: @YES,
		HighlightSearchTermsKey: @YES, 
		TableColumnsHaveBodyPreviewKey: @YES, 
		LastScrollOffsetKey: @0.0,
		LastSelectedPreferencesPaneKey: @"General", 
		StatusBarItem: @NO, 
		KeepsMaxTextWidth: @NO,
		NoteBodyMaxWidth: @660.0f,
		ColorScheme: @2,
		ShowDockIcon: @YES,
		RTLKey: @NO,
		ShowWordCount: @YES,
		markupPreviewMode: @MultiMarkdownPreview,
		UseMarkdownImportKey: @NO,
		UseReadabilityKey: @NO,
		ShowGridKey: @YES,
		AlternatingRowsKey: @NO,
		UseAutoPairing: @NO,
		UseETScrollbarsOnLion: @NO,
		UsesMarkdownCompletions: @NO,
		NoteBodyFontKey: [NSArchiver archivedDataWithRootObject:[NSFont fontWithName:@"Helvetica" size:12.0f]],
		ForegroundTextColorKey: [NSArchiver archivedDataWithRootObject:[NSColor blackColor]],
		BackgroundTextColorKey: [NSArchiver archivedDataWithRootObject:[NSColor whiteColor]],
		SearchTermHighlightColorKey: [NSArchiver archivedDataWithRootObject:[NSColor colorWithCalibratedRed:0.945 green:0.702 blue:0.702 alpha:1.0f]],
		TableFontSizeKey: @([NSFont smallSystemFontSize]),
		NoteAttributesVisibleKey: @[
			NoteTitleColumnString, NoteDateModifiedColumnString
		],
		TableSortColumnKey: NoteDateModifiedColumnString,
		TableIsReverseSortedKey: @YES}
	 ];
	
	autoCompleteSearches = [defaults boolForKey:AutoCompleteSearchesKey];

	return self;
}

+ (GlobalPrefs *)defaultPrefs {
	static GlobalPrefs *prefs = nil;
	if (!prefs)
		prefs = [[GlobalPrefs alloc] init];
	return prefs;
}

- (void)dealloc {
	
	[tableColumns release];
	[super dealloc];
}

- (void)registerTarget:(id <GlobalPrefsObserver>)sender forChangesInSettings:(SEL)firstSEL, ... {
	NSAssert(firstSEL != NULL, @"need at least one selector");

	if (![sender conformsToProtocol:@protocol(GlobalPrefsObserver)]) {
		NSLog(@"%@: target %@ does not respond to callback selector!", NSStringFromSelector(_cmd), [sender description]);
		return;
	}

	va_list argList;
	va_start(argList, firstSEL);
	SEL aSEL = firstSEL;
	do {
		NSString *selectorKey = NSStringFromSelector(aSEL);

		NSHashTable *senders = selectorObservers[selectorKey];
		if (!senders) {
			senders = [NSHashTable weakObjectsHashTable];
			selectorObservers[selectorKey] = senders;
		}

		[senders addObject:sender];
	} while ((aSEL = va_arg(argList, SEL)) != NULL);
	va_end(argList);
}

- (void)unregisterForNotificationsFromSelector:(SEL)selector sender:(id <GlobalPrefsObserver>)sender {
	NSString *selectorKey = NSStringFromSelector(selector);
	
	NSMutableArray *senders = selectorObservers[selectorKey];
	if (senders) {
		[senders removeObjectIdenticalTo:sender];
		
		if (![senders count])
			[selectorObservers removeObjectForKey:selectorKey];
	} else {
		NSLog(@"Selector %@ has no observers?", NSStringFromSelector(selector));
	}
}

- (void)notifyCallbacksForSelector:(SEL)selector excludingSender:(id)sender {
	if ([sender isEqual:self]) { return; }

	for (id <GlobalPrefsObserver> observer in selectorObservers[NSStringFromSelector(selector)]) {
		if ([observer isEqual:sender]) { continue; }
		[observer settingChangedForSelector:selector];
	}
}

- (void)setNotationPrefs:(NotationPrefs*)newNotationPrefs sender:(id)sender {
	[notationPrefs autorelease];
	notationPrefs = [newNotationPrefs retain];
	
	[self resolveNoteBodyFontFromNotationPrefsFromSender:sender];
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (NotationPrefs*)notationPrefs {
	return notationPrefs;
}

- (BOOL)autoCompleteSearches {
	return autoCompleteSearches;
}

- (void)setAutoCompleteSearches:(BOOL)value sender:(id)sender {
	autoCompleteSearches = value;
	[defaults setBool:value forKey:AutoCompleteSearchesKey];

	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (void)setTabIndenting:(BOOL)value sender:(id)sender {
    [defaults setBool:value forKey:TabKeyIndentsKey];

	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (BOOL)tabKeyIndents {
    return [defaults boolForKey:TabKeyIndentsKey];
}

- (void)setUseTextReplacement:(BOOL)value sender:(id)sender {
    [defaults setBool:value forKey:TextReplacementInNoteBodyKey];
    
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (BOOL)useTextReplacement {
    return [defaults boolForKey:TextReplacementInNoteBodyKey];
}

- (void)setCheckSpellingAsYouType:(BOOL)value sender:(id)sender {
    [defaults setBool:value forKey:CheckSpellingInNoteBodyKey];
    
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (BOOL)checkSpellingAsYouType {
    return [defaults boolForKey:CheckSpellingInNoteBodyKey];
}

- (void)setConfirmNoteDeletion:(BOOL)value sender:(id)sender {
    [defaults setBool:value forKey:ConfirmNoteDeletionKey];
    
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (BOOL)confirmNoteDeletion {
    return [defaults boolForKey:ConfirmNoteDeletionKey];
}

- (void)setQuitWhenClosingWindow:(BOOL)value sender:(id)sender {
    [defaults setBool:value forKey:QuitWhenClosingMainWindowKey];
    
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (BOOL)quitWhenClosingWindow {
    return [defaults boolForKey:QuitWhenClosingMainWindowKey];
}

- (void)setAppActivationKeyCombo:(PTKeyCombo*)aCombo sender:(id)sender {
	if (aCombo) {
		[appActivationKeyCombo release];
		appActivationKeyCombo = [aCombo retain];
		
		[[self appActivationHotKey] setKeyCombo:appActivationKeyCombo];
	
		[defaults setInteger:[aCombo keyCode] forKey:AppActivationKeyCodeKey];
		[defaults setInteger:[aCombo modifiers] forKey:AppActivationModifiersKey];
		
		[self notifyCallbacksForSelector:_cmd excludingSender:sender];
	}
}

- (PTHotKey*)appActivationHotKey {
	if (!appActivationHotKey) {
		appActivationHotKey = [[PTHotKey alloc] init];
		[appActivationHotKey setName:HotKeyAppToFrontName];
		[appActivationHotKey setKeyCombo:[self appActivationKeyCombo]];
	}
	
	return appActivationHotKey;
}

- (PTKeyCombo*)appActivationKeyCombo {
	if (!appActivationKeyCombo) {
		appActivationKeyCombo = [[PTKeyCombo alloc] initWithKeyCode:[[defaults objectForKey:AppActivationKeyCodeKey] intValue]
														  modifiers:[[defaults objectForKey:AppActivationModifiersKey] intValue]];
	}
	return appActivationKeyCombo;
}

- (BOOL)registerAppActivationKeystrokeWithTarget:(id)target selector:(SEL)selector {
	PTHotKey *hotKey = [self appActivationHotKey];
	
	[hotKey setTarget:target];
	[hotKey setAction:selector];
	
	[[PTHotKeyCenter sharedCenter] unregisterHotKeyForName:HotKeyAppToFrontName];
	
	return [[PTHotKeyCenter sharedCenter] registerHotKey:hotKey];
}

- (void)setPastePreservesStyle:(BOOL)value sender:(id)sender {
    [defaults setBool:value forKey:PastePreservesStyleKey];
    
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (BOOL)pastePreservesStyle {
    
    return [defaults boolForKey:PastePreservesStyleKey];
}

- (void)setAutoFormatsDoneTag:(BOOL)value sender:(id)sender {
    [defaults setBool:value forKey:AutoFormatsDoneTagKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (BOOL)autoFormatsDoneTag {
	return [defaults boolForKey:AutoFormatsDoneTagKey];
}
- (BOOL)autoFormatsListBullets {
	return [defaults boolForKey:AutoFormatsListBulletsKey];
}
- (void)setAutoFormatsListBullets:(BOOL)value sender:(id)sender {
	[defaults setBool:value forKey:AutoFormatsListBulletsKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (BOOL)autoIndentsNewLines {
	return [defaults boolForKey:AutoIndentsNewLinesKey];
}
- (void)setAutoIndentsNewLines:(BOOL)value sender:(id)sender {
	[defaults setBool:value forKey:AutoIndentsNewLinesKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (void)setLinksAutoSuggested:(BOOL)value sender:(id)sender {
    [defaults setBool:value forKey:AutoSuggestLinksKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (BOOL)linksAutoSuggested {
    return [defaults boolForKey:AutoSuggestLinksKey];
}

- (void)setMakeURLsClickable:(BOOL)value sender:(id)sender {
	[defaults setBool:value forKey:MakeURLsClickableKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (BOOL)URLsAreClickable {
	return [defaults boolForKey:MakeURLsClickableKey];
}

- (void)setRTL:(BOOL)value sender:(id)sender {
	[defaults setBool:value forKey:RTLKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (BOOL)rtl {
	return [defaults boolForKey:RTLKey];
}

- (BOOL)showWordCount{
	return [defaults boolForKey:ShowWordCount];
}

- (void)setShowWordCount:(BOOL)value{
	[defaults setBool:value forKey:ShowWordCount];
}

- (void)setUseETScrollbarsOnLion:(BOOL)value sender:(id)sender{
	[defaults setBool:value forKey:UseETScrollbarsOnLion];
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (BOOL)useETScrollbarsOnLion{
	return [defaults boolForKey:UseETScrollbarsOnLion];
}


- (void)setUseMarkdownImport:(BOOL)value sender:(id)sender {
	[defaults setBool:value forKey:UseMarkdownImportKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (BOOL)useMarkdownImport {
	return [defaults boolForKey:UseMarkdownImportKey];
}
- (void)setUseReadability:(BOOL)value sender:(id)sender {
	[defaults setBool:value forKey:UseReadabilityKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (BOOL)useReadability {
	return [defaults boolForKey:UseReadabilityKey];
}

- (void)setShowGrid:(BOOL)value sender:(id)sender {
	[defaults setBool:value forKey:ShowGridKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (BOOL)showGrid {
	return [defaults boolForKey:ShowGridKey];
}
- (void)setAlternatingRows:(BOOL)value sender:(id)sender {
	[defaults setBool:value forKey:AlternatingRowsKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (BOOL)alternatingRows {
	return [defaults boolForKey:AlternatingRowsKey];
}

- (void)setUseAutoPairing:(BOOL)value{
    [defaults setBool:value forKey:UseAutoPairing];
}

- (BOOL)useAutoPairing{
	return [defaults boolForKey:UseAutoPairing];
}

- (void)setShouldHighlightSearchTerms:(BOOL)shouldHighlight sender:(id)sender {
	[defaults setBool:shouldHighlight forKey:HighlightSearchTermsKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (BOOL)highlightSearchTerms {
	return [defaults boolForKey:HighlightSearchTermsKey];
}

- (void)setSearchTermHighlightColor:(NSColor*)color sender:(id)sender {
	if (color) {
		
		[searchTermHighlightAttributes release];
		searchTermHighlightAttributes = nil;
		
		[defaults setObject:[NSArchiver archivedDataWithRootObject:color] forKey:SearchTermHighlightColorKey];
		
		[self notifyCallbacksForSelector:_cmd excludingSender:sender];
	}
}

- (NSColor*)searchTermHighlightColorRaw:(BOOL)isRaw {
	
	NSData *theData = [defaults dataForKey:SearchTermHighlightColorKey];
	if (theData) {
		NSColor *color = (NSColor *)[NSUnarchiver unarchiveObjectWithData:theData];
		if (isRaw) return color;
		if (color) {
			//nslayoutmanager temporary attributes don't seem to like alpha components, so synthesize translucency using the bg color
			NSColor *fauxAlphaSTHC = [[color colorUsingColorSpaceName:NSCalibratedRGBColorSpace] colorWithAlphaComponent:1.0];
			return [fauxAlphaSTHC blendedColorWithFraction:(1.0 - [color alphaComponent]) ofColor:[self backgroundTextColor]];
		}
	}

	return nil;
}

- (NSDictionary*)searchTermHighlightAttributes {
	NSColor *highlightColor = nil;
	
	if (!searchTermHighlightAttributes && (highlightColor = [self searchTermHighlightColorRaw:NO])) {
		searchTermHighlightAttributes = [@{
			NSBackgroundColorAttributeName: highlightColor
		} retain];
	}
	return searchTermHighlightAttributes;
	
}

- (void)setUseFinderTags:(BOOL)value sender:(id)sender {
	if (!IsMavericksOrLater) {
		[defaults setBool:NO forKey:UseFinderTagsKey];
		return;
	}
	[defaults setBool:value forKey:UseFinderTagsKey];
}

- (BOOL)useFinderTags
{
	return [defaults boolForKey:UseFinderTagsKey];
}

- (void)setSoftTabs:(BOOL)value sender:(id)sender {
	[defaults setBool:value forKey:UseSoftTabsKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (BOOL)softTabs {
	return [defaults boolForKey:UseSoftTabsKey];
}

- (NSInteger)numberOfSpacesInTab {
	return [defaults integerForKey:NumberOfSpacesInTabKey];
}

BOOL ColorsEqualWith8BitChannels(NSColor *c1, NSColor *c2) {
	//sometimes floating point numbers really don't like to be compared to each other

	CGFloat pRed, pGreen, pBlue, gRed, gGreen, gBlue, pAlpha, gAlpha;
	[[c1 colorUsingColorSpaceName:NSCalibratedRGBColorSpace] getRed:&pRed green:&pGreen blue:&pBlue alpha:&pAlpha];
	[[c2 colorUsingColorSpaceName:NSCalibratedRGBColorSpace] getRed:&gRed green:&gGreen blue:&gBlue alpha:&gAlpha];
    
    BOOL(^equalComponents)(CGFloat, CGFloat) = ^BOOL(CGFloat a, CGFloat b){
        return lround(a * 255.) == lround(b * 255.);
    };
    
    if (!equalComponents(pRed, gRed)) { return NO; }
    if (!equalComponents(pBlue, gBlue)) { return NO; }
    if (!equalComponents(pGreen, gGreen)) { return NO; }
    if (!equalComponents(pAlpha, gAlpha)) { return NO; }
    return YES;
}

- (void)resolveNoteBodyFontFromNotationPrefsFromSender:(id)sender {
	
	NSFont *prefsFont = [notationPrefs baseBodyFont];
	if (prefsFont) {
		NSFont *noteFont = [self noteBodyFont];
		
		if (![[prefsFont fontName] isEqualToString:[noteFont fontName]] || 
			!NTVFloatsEqual([prefsFont pointSize], [noteFont pointSize])) {
			
			NSLog(@"archived notationPrefs base font does not match current global default font!");
			[self _setNoteBodyFont:prefsFont];
			
			[self notifyCallbacksForSelector:_cmd excludingSender:sender];
		}
	}
}

- (void)_setNoteBodyFont:(NSFont*)aFont {
	NSFont *oldFont = noteBodyFont;
	noteBodyFont = [aFont retain];
	
	[noteBodyParagraphStyle release];
	noteBodyParagraphStyle = nil;
	
	[noteBodyAttributes release];
	noteBodyAttributes = nil; //cause method to re-update
	
	[defaults setObject:[NSArchiver archivedDataWithRootObject:noteBodyFont] forKey:NoteBodyFontKey]; 
	
	//restyle any PTF data on the clipboard to the new font
	NSData *ptfData = [[NSPasteboard generalPasteboard] dataForType:NVPTFPboardType];
	NSMutableAttributedString *newString = [[[NSMutableAttributedString alloc] initWithRTF:ptfData documentAttributes:nil] autorelease];
	
	[newString restyleTextToFont:noteBodyFont usingBaseFont:oldFont];
	
	if ((ptfData = [newString RTFFromRange:NSMakeRange(0, [newString length]) documentAttributes:nil])) {
		[[NSPasteboard generalPasteboard] setData:ptfData forType:NVPTFPboardType];
	}
	[oldFont release];
}

- (void)setNoteBodyFont:(NSFont*)aFont sender:(id)sender {
	
	if (aFont) {
		[self _setNoteBodyFont:aFont];
		
		[self notifyCallbacksForSelector:_cmd excludingSender:sender];
	}
}

- (NSFont*)noteBodyFont {
	BOOL triedOnce = NO;
	
	if (!noteBodyFont) {
		retry:
		@try {
			noteBodyFont = [[NSUnarchiver unarchiveObjectWithData:[defaults objectForKey:NoteBodyFontKey]] retain];
		} @catch (NSException *e) {
			NSLog(@"Error trying to unarchive default note body font (%@, %@)", [e name], [e reason]);
		}
		
		if ((!noteBodyFont || ![noteBodyFont isKindOfClass:[NSFont class]]) && !triedOnce) {
			triedOnce = YES;
			[defaults removeObjectForKey:NoteBodyFontKey];
			goto retry;
		}
	}
	
    return noteBodyFont;
}

- (NSDictionary*)noteBodyAttributes {
	NSFont *bodyFont = [self noteBodyFont];
	if (!noteBodyAttributes && bodyFont) {
		//NSLog(@"notebody att2");
		
		NSMutableDictionary *attrs = [[NSMutableDictionary dictionaryWithObjectsAndKeys:bodyFont, NSFontAttributeName, nil] retain];
		
		//not storing the foreground color in each note will make the database smaller, and black is assumed when drawing text
		NSColor *fgColor = [NTVAppDelegate() foregrndColor];
		
		if (!ColorsEqualWith8BitChannels([NSColor blackColor], fgColor)) {
			attrs[NSForegroundColorAttributeName] = fgColor;
		}
		// background text color is handled directly by the NSTextView subclass and so does not need to be stored here
		if ([self _bodyFontIsMonospace]) {
			
		//	NSLog(@"notebody att3");
			NSParagraphStyle *pStyle = [self noteBodyParagraphStyle];
			if (pStyle)
				attrs[NSParagraphStyleAttributeName] = pStyle;
		}
		noteBodyAttributes = attrs;
	}else {
		NSMutableDictionary *attrs = [[NSMutableDictionary dictionaryWithObjectsAndKeys:bodyFont, NSFontAttributeName, nil] retain];
		NSColor *fgColor = [NTVAppDelegate() foregrndColor];
		
		attrs[NSForegroundColorAttributeName] = fgColor;
		noteBodyAttributes = attrs;
	}

	return noteBodyAttributes;
}

- (BOOL)_bodyFontIsMonospace {
	NSString *name = [noteBodyFont fontName];
	return (([noteBodyFont isFixedPitch] || [name caseInsensitiveCompare:@"Osaka-Mono"] == NSOrderedSame) && 
			[name caseInsensitiveCompare:@"MS-PGothic"] != NSOrderedSame);
}

- (NSParagraphStyle*)noteBodyParagraphStyle {
	NSFont *bodyFont = [self noteBodyFont];

	if (!noteBodyParagraphStyle && bodyFont) {
		NSInteger numberOfSpaces = [self numberOfSpacesInTab];
		NSMutableString *sizeString = [[NSMutableString alloc] initWithCapacity:numberOfSpaces];
		while (numberOfSpaces--) {
			[sizeString appendString:@" "];
		}
        NSDictionary *sizeAttribute = @{
			NSFontAttributeName: bodyFont
		};
		CGFloat sizeOfTab = [sizeString sizeWithAttributes:sizeAttribute].width;
		[sizeString release];
		
		noteBodyParagraphStyle = [[NSParagraphStyle defaultParagraphStyle] mutableCopy];
		
		NSTextTab *textTabToBeRemoved;
		NSEnumerator *enumerator = [[noteBodyParagraphStyle tabStops] objectEnumerator];
		while ((textTabToBeRemoved = [enumerator nextObject])) {
			[noteBodyParagraphStyle removeTabStop:textTabToBeRemoved];
		}
		//[paragraphStyle setHeadIndent:sizeOfTab]; //for soft-indents, this would probably have to be applied contextually, and heaven help us for soft tabs

		[noteBodyParagraphStyle setDefaultTabInterval:sizeOfTab];
	}
	
	return noteBodyParagraphStyle;
}

- (void)setForegroundTextColor:(NSColor*)aColor sender:(id)sender {
	if (aColor) {
		[noteBodyAttributes release];
		noteBodyAttributes = nil;
		
		[defaults setObject:[NSArchiver archivedDataWithRootObject:aColor] forKey:ForegroundTextColorKey];
		
		[self notifyCallbacksForSelector:_cmd excludingSender:sender];
	}	
}

- (NSColor*)foregroundTextColor {
	NSData *theData = [defaults dataForKey:ForegroundTextColorKey];
	if (theData) return (NSColor *)[NSUnarchiver unarchiveObjectWithData:theData];
	return nil;
}

- (void)setBackgroundTextColor:(NSColor*)aColor sender:(id)sender {
	
	if (aColor) {
		//highlight color is based on blended-alpha version of background color
		//(because nslayoutmanager temporary attributes don't seem to like alpha components)
		//so it's necessary to invalidate the effective cache of that computed highlight color
		[searchTermHighlightAttributes release];
		searchTermHighlightAttributes = nil;

		[defaults setObject:[NSArchiver archivedDataWithRootObject:aColor] forKey:BackgroundTextColorKey];
	
		[self notifyCallbacksForSelector:_cmd excludingSender:sender];
	}
}

- (NSColor*)backgroundTextColor {
	//don't need to cache the unarchived color, as it's not used in a random-access pattern
	
	NSData *theData = [defaults dataForKey:BackgroundTextColorKey];
	if (theData) return (NSColor *)[NSUnarchiver unarchiveObjectWithData:theData];

	return nil;	
}

- (BOOL)tableColumnsShowPreview {
	return [defaults boolForKey:TableColumnsHaveBodyPreviewKey];
}

- (void)setTableColumnsShowPreview:(BOOL)showPreview sender:(id)sender {
	[defaults setBool:showPreview forKey:TableColumnsHaveBodyPreviewKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (CGFloat)tableFontSize {
	NSNumber *value = [defaults objectForKey:TableFontSizeKey];
#if CGFLOAT_IS_DOUBLE
	return [value doubleValue];
#else
	return [value floatValue];
#endif
}

- (void)setTableFontSize:(CGFloat)fontSize sender:(id)sender {
	[defaults setObject:@(fontSize) forKey:TableFontSizeKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (void)removeTableColumn:(NSString*)columnKey sender:(id)sender {
	[tableColumns removeObject:columnKey];
	tableColsBitmap = 0U;
	
	[defaults setObject:tableColumns forKey:NoteAttributesVisibleKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}
- (void)addTableColumn:(NSString*)columnKey sender:(id)sender {
	if (![tableColumns containsObject:columnKey]) {
		[tableColumns addObject:columnKey];
		tableColsBitmap = 0U;
		
		[defaults setObject:tableColumns forKey:NoteAttributesVisibleKey];
		
		[self notifyCallbacksForSelector:_cmd excludingSender:sender];
	}
}

- (NSArray*)visibleTableColumns {
	if (!tableColumns) {
		tableColumns = [[NSMutableArray arrayWithArray:[defaults arrayForKey:NoteAttributesVisibleKey]] retain];
		tableColsBitmap = 0U;
	}
	
	if (![tableColumns count])
		[self addTableColumn:NoteTitleColumnString sender:self];
		
	return tableColumns;
}


- (unsigned int)tableColumnsBitmap {
	if (tableColsBitmap == 0U) {
		if ([tableColumns containsObject:NoteTitleColumnString])
			tableColsBitmap = (tableColsBitmap | (1 << NoteTitleColumn));
		if ([tableColumns containsObject:NoteLabelsColumnString])
			tableColsBitmap = (tableColsBitmap | (1 << NoteLabelsColumn));
		if ([tableColumns containsObject:NoteDateModifiedColumnString])
			tableColsBitmap = (tableColsBitmap | (1 << NoteDateModifiedColumn));
		if ([tableColumns containsObject:NoteDateCreatedColumnString])
			tableColsBitmap = (tableColsBitmap | (1 << NoteDateCreatedColumn));		
	}
	return tableColsBitmap;
}

- (void)setSortedTableColumnKey:(NSString*)sortedKey reversed:(BOOL)reversed sender:(id)sender {
	[defaults setBool:reversed forKey:TableIsReverseSortedKey];
    [defaults setObject:sortedKey forKey:TableSortColumnKey];
    
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (NSString*)sortedTableColumnKey {
    return [defaults objectForKey:TableSortColumnKey];
}

- (BOOL)tableIsReverseSorted {
    return [defaults boolForKey:TableIsReverseSortedKey];
}

- (void)setHorizontalLayout:(BOOL)value sender:(id)sender {
	if ([self horizontalLayout] != value) {
		[defaults setBool:value forKey:HorizontalLayoutKey];
		
		[self notifyCallbacksForSelector:_cmd excludingSender:sender];
	}
}
- (BOOL)horizontalLayout {
	return [defaults boolForKey:HorizontalLayoutKey];
}

- (NSString*)lastSelectedPreferencesPane {
	return [defaults stringForKey:LastSelectedPreferencesPaneKey];
}
- (void)setLastSelectedPreferencesPane:(NSString*)pane sender:(id)sender {
	[defaults setObject:pane forKey:LastSelectedPreferencesPaneKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (void)setLastSearchString:(NSString*)string selectedNote:(id<SynchronizedNote>)aNote scrollOffsetForTableView:(NotesTableView*)tv sender:(id)sender {
	
	NSMutableString *stringMinusBreak = [[string mutableCopy] autorelease];
	[stringMinusBreak replaceOccurrencesOfString:@"\n" withString:@" " options:NSLiteralSearch range:NSMakeRange(0, [stringMinusBreak length])];
	
	[defaults setObject:stringMinusBreak forKey:LastSearchStringKey];
	
    NSString *uuidString = [NSString ntv_UUIDStringForBytes:aNote.uniqueNoteIDBytes];

	[defaults setObject:uuidString forKey:LastSelectedNoteUUIDBytesKey];
	
	double offset = [tv distanceFromRow:[(FastListDataSource*)[tv dataSource] indexOfObjectIdenticalTo:aNote] forVisibleArea:[tv visibleRect]];
	[defaults setDouble:offset forKey:LastScrollOffsetKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (NSString*)lastSearchString {
	return [defaults objectForKey:LastSearchStringKey];
}

- (CFUUIDBytes)UUIDBytesOfLastSelectedNote {
	CFUUIDBytes bytes;
    if (![[defaults objectForKey:LastSelectedNoteUUIDBytesKey] ntv_getUUIDBytes:&bytes]) {
        bzero(&bytes, sizeof(CFUUIDBytes));
    }
    return bytes;
}

- (CGFloat)scrollOffsetOfLastSelectedNote {
	return [defaults doubleForKey:LastScrollOffsetKey];
}

- (void)saveCurrentBookmarksFromSender:(id)sender {
	//run this during quit and when saved searches change?
	NSArray *bookmarks = [bookmarksController dictionaryReps];
	if (bookmarks) {
		[defaults setObject:bookmarks forKey:BookmarksKey];
		[defaults setBool:[bookmarksController isVisible] forKey:@"BookmarksVisible"];
	}
		
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (BookmarksController*)bookmarksController {
	if (!bookmarksController) {
		bookmarksController = [[BookmarksController alloc] initWithBookmarks:[defaults arrayForKey:BookmarksKey]];
	}
	return bookmarksController;
}

- (void)setAliasDataForDefaultDirectory:(NSData*)alias sender:(id)sender {
    [defaults setObject:alias forKey:DirectoryAliasKey];
	
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (NSData*)aliasDataForDefaultDirectory {
    return [defaults dataForKey:DirectoryAliasKey];
}

- (NSString*)displayNameForDefaultDirectoryWithFSRef:(FSRef*)fsRef {

    if (!fsRef)
	return nil;
    
    if (IsZeros(fsRef, sizeof(FSRef))) {
	if (![[self aliasDataForDefaultDirectory] fsRefAsAlias:fsRef])
	    return nil;
    }
    CFStringRef displayName = NULL;
    if (LSCopyDisplayNameForRef(fsRef, &displayName) == noErr) {
	return [(NSString*)displayName autorelease];
    }
    return nil;
}

- (NSString*)humanViewablePathForDefaultDirectory {
    //resolve alias to fsref
    FSRef targetRef;
    if ([[self aliasDataForDefaultDirectory] fsRefAsAlias:&targetRef]) {	    
	//follow the parent fsrefs up the tree, calling LSCopyDisplayNameForRef, hoping that the root is a drive name
	
	NSMutableArray *directoryNames = [NSMutableArray arrayWithCapacity:4];
	FSRef parentRef, *currentRef = &targetRef;
	
	OSStatus err = noErr;
	
	do {
	    
	    if ((err = FSGetCatalogInfo(currentRef, kFSCatInfoNone, NULL, NULL, NULL, &parentRef)) == noErr) {
		
		CFStringRef displayName = NULL;
		if ((err = LSCopyDisplayNameForRef(currentRef, &displayName)) == noErr) {
		    
		    if (displayName) {
			[directoryNames insertObject:(id)displayName atIndex:0];
			CFRelease(displayName);
		    }
		}
		
		currentRef = &parentRef;
	    }
	} while (err == noErr);
	
	//build new string delimited by triangles like pages in its recent items menu
	return [directoryNames componentsJoinedByString:@" : "];
	
    }
    
    return nil;
}

- (void)setBlorImportAttempted:(BOOL)value {
	[defaults setBool:value forKey:TriedToImportBlorKey];
}

- (BOOL)triedToImportBlor {
	return [defaults boolForKey:TriedToImportBlorKey];
}
- (void)synchronize {
    [defaults synchronize];
}



//elasticthreads' work

- (void)setManagesTextWidthInWindow:(BOOL)manageIt sender:(id)sender{
    [defaults setBool:manageIt forKey:KeepsMaxTextWidth];
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}

- (BOOL)managesTextWidthInWindow{
	return [defaults boolForKey:KeepsMaxTextWidth];
}

- (CGFloat)maxNoteBodyWidth{
	NSNumber *value = [defaults objectForKey:NoteBodyMaxWidth];
#if CGFLOAT_IS_DOUBLE
	return [value doubleValue];
#else
	return [value floatValue];
#endif
}

- (void)setMaxNoteBodyWidth:(CGFloat)maxWidth sender:(id)sender{
	[defaults setObject:@(maxWidth) forKey:NoteBodyMaxWidth];
//	[defaults synchronize];
	[self notifyCallbacksForSelector:_cmd excludingSender:sender];
}



@end
