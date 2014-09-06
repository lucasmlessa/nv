/*
 *  FSExchangeObjectsCompat.h
 *  Notation
 *
 */

@import Carbon;

extern u_int32_t volumeCapabilities(const char *path);
OSErr FSExchangeObjectsEmulate(const FSRef *sourceRef, const FSRef *destRef, FSRef *newSourceRef, FSRef *newDestRef);
Boolean VolumeOfFSRefSupportsExchangeObjects(const FSRef *fsRef);
