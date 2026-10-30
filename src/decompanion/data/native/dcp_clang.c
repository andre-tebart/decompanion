/* dcp_clang: the top-level walk of cparse.model in native code (source/cparse.py, `native`).

   The Python bindings of libclang cost a few microseconds per cursor; a unit of gildegold has ~50000 top-level
   cursors (most of them macro expansions), so the walk took ~0.35 s of a ~0.1 s parse. This library walks the
   same cursors through the same libclang (the module the bindings loaded: dcp_init takes its handle) and writes
   one text record per cursor the model reads, with raw positions (file name, line, byte column of the expansion
   location, what the bindings' SourceLocation gives); cparse maps them exactly as it maps the bindings' own.

   Records, one per line, fields separated by TAB; a position is three fields (file, line, column; an empty file
   for a location without one):
     F  name static definition start location end body knr     a function declaration, no inline helper;
        body: a position or `-` `-` `-`; knr: `-` without a body, else the parameters `name\x1fpromoted` joined
        by \x1e (promoted: int / double for a type the K&R default promotion changes, else empty)
     V  name static kind start location end init aggregate     a data declarator (kind def / extern)
     T  name enum location                                     a typedef, a struct / union / enum with a body
     E  name location                                          an enum constant of the T record before it
     M  name location function-like                            a macro definition
   Built by tools/build_native.py; the ABI is the C API of libclang (clang-c/Index.h), stable across versions. */
#include <clang-c/Index.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define API(ret, name, args) static ret (*p_##name) args;
API(CXCursor, clang_getTranslationUnitCursor, (CXTranslationUnit))
API(unsigned, clang_visitChildren, (CXCursor, CXCursorVisitor, CXClientData))
API(enum CXCursorKind, clang_getCursorKind, (CXCursor))
API(CXString, clang_getCursorSpelling, (CXCursor))
API(const char *, clang_getCString, (CXString))
API(void, clang_disposeString, (CXString))
API(CXSourceLocation, clang_getCursorLocation, (CXCursor))
API(CXSourceRange, clang_getCursorExtent, (CXCursor))
API(CXSourceLocation, clang_getRangeStart, (CXSourceRange))
API(CXSourceLocation, clang_getRangeEnd, (CXSourceRange))
API(void, clang_getExpansionLocation, (CXSourceLocation, CXFile *, unsigned *, unsigned *, unsigned *))
API(CXString, clang_getFileName, (CXFile))
API(unsigned, clang_Cursor_isFunctionInlined, (CXCursor))
API(unsigned, clang_Cursor_isMacroFunctionLike, (CXCursor))
API(enum CX_StorageClass, clang_Cursor_getStorageClass, (CXCursor))
API(unsigned, clang_isCursorDefinition, (CXCursor))
API(int, clang_Cursor_getNumArguments, (CXCursor))
API(CXCursor, clang_Cursor_getArgument, (CXCursor, unsigned))
API(CXType, clang_getCursorType, (CXCursor))
API(CXType, clang_getCanonicalType, (CXType))
API(unsigned, clang_isExpression, (enum CXCursorKind))

typedef struct { char *p; size_t n, cap; } Buf;

static void put(Buf *b, const char *s, size_t n) {
    if (b->n + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 1 << 20;
        while (b->n + n + 1 > cap) cap *= 2;
        b->p = realloc(b->p, cap);
        b->cap = cap;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}

static void puts_(Buf *b, const char *s) { put(b, s, strlen(s)); }

static void putu(Buf *b, unsigned long long v) {
    char t[32];
    put(b, t, (size_t)sprintf(t, "%llu", v));
}

static void spelling(Buf *b, CXCursor c) {
    CXString s = p_clang_getCursorSpelling(c);
    puts_(b, p_clang_getCString(s));
    p_clang_disposeString(s);
}

/* a position: TAB file TAB line TAB column (the expansion location, as the bindings' SourceLocation) */
static void pos(Buf *b, CXSourceLocation loc) {
    CXFile f;
    unsigned line, col, off;
    p_clang_getExpansionLocation(loc, &f, &line, &col, &off);
    put(b, "\t", 1);
    if (f) {
        CXString s = p_clang_getFileName(f);
        puts_(b, p_clang_getCString(s));
        p_clang_disposeString(s);
    }
    put(b, "\t", 1);
    putu(b, line);
    put(b, "\t", 1);
    putu(b, col);
}

static void flag(Buf *b, int v) { put(b, v ? "\t1" : "\t0", 2); }

static enum CXChildVisitResult find_body(CXCursor c, CXCursor parent, CXClientData d) {
    (void)parent;
    if (p_clang_getCursorKind(c) == CXCursor_CompoundStmt) {
        *(CXCursor *)d = c;
        return CXChildVisit_Break;
    }
    return CXChildVisit_Continue;
}

static enum CXChildVisitResult any_expression(CXCursor c, CXCursor parent, CXClientData d) {
    (void)parent;
    if (p_clang_isExpression(p_clang_getCursorKind(c))) {
        *(int *)d = 1;
        return CXChildVisit_Break;
    }
    return CXChildVisit_Continue;
}

static enum CXChildVisitResult enum_constants(CXCursor c, CXCursor parent, CXClientData d) {
    (void)parent;
    if (p_clang_getCursorKind(c) == CXCursor_EnumConstantDecl) {
        Buf *b = d;
        puts_(b, "E\t");
        spelling(b, c);
        pos(b, p_clang_getCursorLocation(c));
        put(b, "\n", 1);
    }
    return CXChildVisit_Continue;
}

static const char *promoted(enum CXTypeKind k) {
    switch (k) {
    case CXType_Char_S: case CXType_Char_U: case CXType_SChar: case CXType_UChar: case CXType_Short: case CXType_UShort:
        return "int";
    case CXType_Float:
        return "double";
    default:
        return "";
    }
}

static enum CXChildVisitResult top(CXCursor c, CXCursor parent, CXClientData d) {
    Buf *b = d;
    enum CXCursorKind k = p_clang_getCursorKind(c);
    (void)parent;
    if (k == CXCursor_FunctionDecl) {
        CXSourceRange ext;
        CXCursor body = {0};
        if (p_clang_Cursor_isFunctionInlined(c))
            return CXChildVisit_Continue;
        ext = p_clang_getCursorExtent(c);
        puts_(b, "F\t");
        spelling(b, c);
        flag(b, p_clang_Cursor_getStorageClass(c) == CX_SC_Static);
        flag(b, p_clang_isCursorDefinition(c) != 0);
        pos(b, p_clang_getRangeStart(ext));
        pos(b, p_clang_getCursorLocation(c));
        pos(b, p_clang_getRangeEnd(ext));
        body.kind = CXCursor_InvalidFile;
        p_clang_visitChildren(c, find_body, &body);
        if (body.kind == CXCursor_CompoundStmt) {
            int i, n = p_clang_Cursor_getNumArguments(c);
            pos(b, p_clang_getRangeStart(p_clang_getCursorExtent(body)));
            put(b, "\t", 1);
            if (n < 0) n = 0;
            for (i = 0; i < n; i++) {
                CXCursor a = p_clang_Cursor_getArgument(c, (unsigned)i);
                if (i) put(b, "\x1e", 1);
                spelling(b, a);
                put(b, "\x1f", 1);
                puts_(b, promoted(p_clang_getCanonicalType(p_clang_getCursorType(a)).kind));
            }
        } else {
            puts_(b, "\t-\t-\t-\t-");
        }
        put(b, "\n", 1);
    } else if (k == CXCursor_VarDecl) {
        CXSourceRange ext = p_clang_getCursorExtent(c);
        enum CX_StorageClass sc = p_clang_Cursor_getStorageClass(c);
        enum CXTypeKind tk = p_clang_getCanonicalType(p_clang_getCursorType(c)).kind;
        int init = 0;
        puts_(b, "V\t");
        spelling(b, c);
        flag(b, sc == CX_SC_Static);
        puts_(b, p_clang_isCursorDefinition(c) || sc != CX_SC_Extern ? "\tdef" : "\textern");
        pos(b, p_clang_getRangeStart(ext));
        pos(b, p_clang_getCursorLocation(c));
        pos(b, p_clang_getRangeEnd(ext));
        p_clang_visitChildren(c, any_expression, &init);
        flag(b, init);
        flag(b, tk == CXType_ConstantArray || tk == CXType_IncompleteArray || tk == CXType_VariableArray
                    || tk == CXType_Record);
        put(b, "\n", 1);
    } else if (k == CXCursor_TypedefDecl || ((k == CXCursor_StructDecl || k == CXCursor_UnionDecl || k == CXCursor_EnumDecl)
                                             && p_clang_isCursorDefinition(c))) {
        CXString s = p_clang_getCursorSpelling(c);
        const char *name = p_clang_getCString(s);
        if (k == CXCursor_TypedefDecl || name[0]) {
            puts_(b, "T\t");
            puts_(b, name);
            flag(b, k == CXCursor_EnumDecl);
            pos(b, p_clang_getCursorLocation(c));
            put(b, "\n", 1);
            if (k == CXCursor_EnumDecl)
                p_clang_visitChildren(c, enum_constants, b);
        }
        p_clang_disposeString(s);
    } else if (k == CXCursor_MacroDefinition) {
        puts_(b, "M\t");
        spelling(b, c);
        pos(b, p_clang_getCursorLocation(c));
        flag(b, p_clang_Cursor_isMacroFunctionLike(c) != 0);
        put(b, "\n", 1);
    }
    return CXChildVisit_Continue;
}

#define LOAD(name) if (!(p_##name = (void *)GetProcAddress(m, #name))) return 0;

/* the libclang module the Python bindings loaded; 1 when every function was found */
__declspec(dllexport) int dcp_init(void *module) {
    HMODULE m = (HMODULE)module;
    LOAD(clang_getTranslationUnitCursor) LOAD(clang_visitChildren) LOAD(clang_getCursorKind)
    LOAD(clang_getCursorSpelling) LOAD(clang_getCString) LOAD(clang_disposeString) LOAD(clang_getCursorLocation)
    LOAD(clang_getCursorExtent) LOAD(clang_getRangeStart) LOAD(clang_getRangeEnd) LOAD(clang_getExpansionLocation)
    LOAD(clang_getFileName) LOAD(clang_Cursor_isFunctionInlined) LOAD(clang_Cursor_isMacroFunctionLike)
    LOAD(clang_Cursor_getStorageClass) LOAD(clang_isCursorDefinition) LOAD(clang_Cursor_getNumArguments)
    LOAD(clang_Cursor_getArgument) LOAD(clang_getCursorType) LOAD(clang_getCanonicalType) LOAD(clang_isExpression)
    return 1;
}

/* the records of a translation unit's top-level cursors; *n their length; free with dcp_free */
__declspec(dllexport) char *dcp_model_walk(CXTranslationUnit tu, size_t *n) {
    Buf b = {0};
    put(&b, "", 0);
    p_clang_visitChildren(p_clang_getTranslationUnitCursor(tu), top, &b);
    *n = b.n;
    return b.p;
}

__declspec(dllexport) void dcp_free(char *p) { free(p); }
