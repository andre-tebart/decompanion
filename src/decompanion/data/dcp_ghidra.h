/* dcp_ghidra.h: the type names and helper macros of Ghidra's pseudocode, so that a draft `dcp draft` wrote from a
   Ghidra draft compiles (written by dcp draft into include/; a function is readable once none of these is left
   in it: replace them by the real types as the function gets its meaning) */
#ifndef DCP_GHIDRA_H
#define DCP_GHIDRA_H

#include <windows.h>

typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined3;
typedef unsigned int undefined4;
typedef unsigned __int64 undefined8;
#ifndef __RPCNDR_H__
typedef unsigned char byte;
#endif
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned short word;
typedef unsigned long dword;
typedef __int64 longlong;
typedef unsigned __int64 ulonglong;
typedef unsigned int uint3;
typedef int code();
#ifndef __cplusplus
typedef unsigned char bool;
#endif
#define true 1
#define false 0

#define CONCAT11(a, b) ((unsigned short)(((unsigned short)(unsigned char)(a) << 8) | (unsigned char)(b)))
#define CONCAT12(a, b) ((unsigned int)(((unsigned int)(unsigned char)(a) << 16) | (unsigned short)(b)))
#define CONCAT13(a, b) ((unsigned int)(((unsigned int)(unsigned char)(a) << 24) | ((unsigned int)(b) & 0xffffffU)))
#define CONCAT21(a, b) ((unsigned int)(((unsigned int)(unsigned short)(a) << 8) | (unsigned char)(b)))
#define CONCAT22(a, b) ((unsigned int)(((unsigned int)(unsigned short)(a) << 16) | (unsigned short)(b)))
#define CONCAT31(a, b) ((unsigned int)(((unsigned int)(a) << 8) | (unsigned char)(b)))
#define CONCAT44(a, b) ((unsigned __int64)(((unsigned __int64)(unsigned int)(a) << 32) | (unsigned int)(b)))
#define SUB41(x, n) ((unsigned char)((unsigned int)(x) >> ((n) * 8)))
#define SUB42(x, n) ((unsigned short)((unsigned int)(x) >> ((n) * 8)))
#define SUB81(x, n) ((unsigned char)((unsigned __int64)(x) >> ((n) * 8)))
#define SUB84(x, n) ((unsigned int)((unsigned __int64)(x) >> ((n) * 8)))
#define ZEXT14(x) ((unsigned int)(unsigned char)(x))
#define ZEXT24(x) ((unsigned int)(unsigned short)(x))
#define ZEXT48(x) ((unsigned __int64)(unsigned int)(x))
#define SEXT14(x) ((int)(signed char)(x))
#define SEXT24(x) ((int)(short)(x))
#define SEXT48(x) ((__int64)(int)(x))

#endif
