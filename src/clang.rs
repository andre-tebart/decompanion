//! The C front end over libclang: the library loaded at run time from the
//! LLVM installation (its C API, clang-c/Index.h, stable across versions), a translation unit held as a `Unit`,
//! and what the scan and the lint read of one: the model (the top-level declarations, macros, casts and dead
//! ranges per project file), the diagnostics, the references of names to declarations not at file scope, the
//! calling conventions of the system headers' functions. Positions as cparse documents them.

use crate::error::{Error, Result};
use regex::bytes::Regex as BRegex;
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::{c_char, c_int, c_uint, c_ulong, c_void, CStr, CString};
use std::sync::{LazyLock, Mutex, OnceLock};

// ------------------------------------------------------------------------------------------------ the C API

#[repr(C)]
#[derive(Clone, Copy)]
struct CXString {
    data: *const c_void,
    flags: c_uint,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CXCursor {
    kind: c_int,
    xdata: c_int,
    data: [*const c_void; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CXLoc {
    ptr: [*const c_void; 2],
    int: c_uint,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CXRange {
    ptr: [*const c_void; 2],
    begin: c_uint,
    end: c_uint,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CXType {
    kind: c_int,
    data: [*const c_void; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CXToken {
    int: [c_uint; 4],
    ptr: *const c_void,
}

#[repr(C)]
struct CXUnsavedFile {
    name: *const c_char,
    contents: *const c_char,
    length: c_ulong,
}

#[repr(C)]
struct CXRangeList {
    count: c_uint,
    ranges: *const CXRange,
}

type P = *mut c_void;
type Visitor = extern "C" fn(CXCursor, CXCursor, P) -> c_int;
type IncVisitor = extern "C" fn(P, *const CXLoc, c_uint, P);

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> P;
    fn GetProcAddress(module: P, name: *const u8) -> P;
}

macro_rules! api {
    ($($name:ident: fn($($a:ty),*) $(-> $r:ty)?;)*) => {
        #[allow(non_snake_case)]
        struct Api { $($name: unsafe extern "C" fn($($a),*) $(-> $r)?,)* }
        fn load_api(m: P) -> Result<Api, String> {
            unsafe {
                Ok(Api { $($name: {
                    let p = GetProcAddress(m, concat!(stringify!($name), "\0").as_ptr());
                    if p.is_null() {
                        return Err(stringify!($name).to_string());
                    }
                    std::mem::transmute::<P, unsafe extern "C" fn($($a),*) $(-> $r)?>(p)
                },)* })
            }
        }
    };
}

api! {
    clang_createIndex: fn(c_int, c_int) -> P;
    clang_disposeIndex: fn(P);
    clang_parseTranslationUnit: fn(P, *const c_char, *const *const c_char, c_int, *mut CXUnsavedFile, c_uint, c_uint) -> P;
    clang_reparseTranslationUnit: fn(P, c_uint, *mut CXUnsavedFile, c_uint) -> c_int;
    clang_disposeTranslationUnit: fn(P);
    clang_getClangVersion: fn() -> CXString;
    clang_getCString: fn(CXString) -> *const c_char;
    clang_disposeString: fn(CXString);
    clang_getTranslationUnitCursor: fn(P) -> CXCursor;
    clang_visitChildren: fn(CXCursor, Visitor, P) -> c_uint;
    clang_getCursorKind: fn(CXCursor) -> c_int;
    clang_getCursorSpelling: fn(CXCursor) -> CXString;
    clang_getCursorLocation: fn(CXCursor) -> CXLoc;
    clang_getCursorExtent: fn(CXCursor) -> CXRange;
    clang_getRangeStart: fn(CXRange) -> CXLoc;
    clang_getRangeEnd: fn(CXRange) -> CXLoc;
    clang_getRange: fn(CXLoc, CXLoc) -> CXRange;
    clang_getExpansionLocation: fn(CXLoc, *mut P, *mut c_uint, *mut c_uint, *mut c_uint);
    clang_getFileName: fn(P) -> CXString;
    clang_Cursor_isFunctionInlined: fn(CXCursor) -> c_uint;
    clang_Cursor_isMacroFunctionLike: fn(CXCursor) -> c_uint;
    clang_Cursor_getStorageClass: fn(CXCursor) -> c_int;
    clang_isCursorDefinition: fn(CXCursor) -> c_uint;
    clang_Cursor_getNumArguments: fn(CXCursor) -> c_int;
    clang_Cursor_getArgument: fn(CXCursor, c_uint) -> CXCursor;
    clang_getCursorType: fn(CXCursor) -> CXType;
    clang_getCanonicalType: fn(CXType) -> CXType;
    clang_getArrayElementType: fn(CXType) -> CXType;
    clang_Type_getSizeOf: fn(CXType) -> i64;
    clang_isExpression: fn(c_int) -> c_uint;
    clang_getInclusions: fn(P, IncVisitor, P);
    clang_getFile: fn(P, *const c_char) -> P;
    clang_getSkippedRanges: fn(P, P) -> *mut CXRangeList;
    clang_disposeSourceRangeList: fn(*mut CXRangeList);
    clang_getLocationForOffset: fn(P, P, c_uint) -> CXLoc;
    clang_getCursor: fn(P, CXLoc) -> CXCursor;
    clang_Cursor_isNull: fn(CXCursor) -> c_int;
    clang_getCursorReferenced: fn(CXCursor) -> CXCursor;
    clang_getCursorSemanticParent: fn(CXCursor) -> CXCursor;
    clang_getNumDiagnostics: fn(P) -> c_uint;
    clang_getDiagnostic: fn(P, c_uint) -> P;
    clang_disposeDiagnostic: fn(P);
    clang_getDiagnosticSeverity: fn(P) -> c_int;
    clang_getDiagnosticLocation: fn(P) -> CXLoc;
    clang_getDiagnosticSpelling: fn(P) -> CXString;
    clang_getDiagnosticOption: fn(P, *mut CXString) -> CXString;
    clang_getChildDiagnostics: fn(P) -> P;
    clang_getNumDiagnosticsInSet: fn(P) -> c_uint;
    clang_getDiagnosticInSet: fn(P, c_uint) -> P;
    clang_tokenize: fn(P, CXRange, *mut *mut CXToken, *mut c_uint);
    clang_disposeTokens: fn(P, *mut CXToken, c_uint);
    clang_getTokenKind: fn(CXToken) -> c_int;
    clang_getTokenLocation: fn(P, CXToken) -> CXLoc;
    clang_getTokenSpelling: fn(P, CXToken) -> CXString;
    clang_equalLocations: fn(CXLoc, CXLoc) -> c_uint;
    clang_getFunctionTypeCallingConv: fn(CXType) -> c_int;
    clang_getTokenExtent: fn(P, CXToken) -> CXRange;
    clang_getFileLocation: fn(CXLoc, *mut P, *mut c_uint, *mut c_uint, *mut c_uint);
}

// cursor, type, storage, severity, token kinds and options of clang-c/Index.h
const STRUCT_DECL: c_int = 2;
const UNION_DECL: c_int = 3;
const ENUM_DECL: c_int = 5;
const FIELD_DECL: c_int = 6;
const ENUM_CONSTANT_DECL: c_int = 7;
const FUNCTION_DECL: c_int = 8;
const VAR_DECL: c_int = 9;
const PARM_DECL: c_int = 10;
const TYPEDEF_DECL: c_int = 20;
const CSTYLE_CAST_EXPR: c_int = 117;
const LABEL_STMT: c_int = 201;
const COMPOUND_STMT: c_int = 202;
const TRANSLATION_UNIT: c_int = 350;
const MACRO_DEFINITION: c_int = 501;
const T_POINTER: c_int = 101;
const T_RECORD: c_int = 105;
const SC_EXTERN: c_int = 2;
const SC_STATIC: c_int = 3;
const SEV_WARNING: c_int = 2;
const SEV_ERROR: c_int = 3;
const SEV_FATAL: c_int = 4;
const TOKEN_IDENTIFIER: c_int = 2;
const TOKEN_LITERAL: c_int = 3;
const TOKEN_COMMENT: c_int = 4;
const CC_C: c_int = 1;
const BREAK: c_int = 0;
const CONTINUE: c_int = 1;
const DETAILED: c_uint = 0x01;
const PREAMBLE: c_uint = 0x04;
const KEEP_GOING: c_uint = 0x200;

static LIB: OnceLock<(String, Api)> = OnceLock::new();

fn api() -> Result<&'static Api> {
    LIB.get().map(|l| &l.1).ok_or_else(|| Error::runtime("libclang is not loaded (cparse.load)"))
}

pub(crate) fn load(path: &str) -> Result<(), String> {
    if let Some((have, _)) = LIB.get() {
        let norm = |p: &str| crate::project::py_path(p).to_lowercase();
        if norm(have) != norm(path) {
            return Err(format!("libclang {path} asked for, {have} already loaded in this process"));
        }
        return Ok(());
    }
    let wide: Vec<u16> = path.encode_utf16().chain([0]).collect();
    let m = unsafe { LoadLibraryW(wide.as_ptr()) };
    if m.is_null() {
        return Err(format!("libclang {path}: cannot be loaded"));
    }
    let a = load_api(m).map_err(|f| format!("libclang {path} lacks {f}"))?;
    let _ = LIB.set((path.to_string(), a));
    Ok(())
}

/// The loaded libclang's version text.
pub fn clang_version() -> Result<String> {
    let a = api()?;
    Ok(take(a, unsafe { (a.clang_getClangVersion)() }))
}

fn take(a: &Api, s: CXString) -> String {
    unsafe {
        let p = (a.clang_getCString)(s);
        let out = if p.is_null() { String::new() } else { CStr::from_ptr(p).to_string_lossy().into_owned() };
        (a.clang_disposeString)(s);
        out
    }
}

fn spelling(a: &Api, c: CXCursor) -> String {
    take(a, unsafe { (a.clang_getCursorSpelling)(c) })
}

fn is_null(a: &Api, c: CXCursor) -> bool {
    unsafe { (a.clang_Cursor_isNull)(c) != 0 }
}

/// The expansion location: (file name or None, line, byte column), as the bindings' SourceLocation.
fn expand(a: &Api, loc: CXLoc) -> (Option<String>, u32, u32) {
    let (mut f, mut line, mut col, mut off): (P, c_uint, c_uint, c_uint) = (std::ptr::null_mut(), 0, 0, 0);
    unsafe { (a.clang_getExpansionLocation)(loc, &mut f, &mut line, &mut col, &mut off) };
    let name = if f.is_null() { None } else { Some(take(a, unsafe { (a.clang_getFileName)(f) })) };
    (name, line, col)
}

fn visit<F: FnMut(CXCursor) -> c_int>(a: &Api, c: CXCursor, mut f: F) {
    extern "C" fn tramp<F: FnMut(CXCursor) -> c_int>(c: CXCursor, _p: CXCursor, d: P) -> c_int {
        unsafe { (*(d as *mut F))(c) }
    }
    unsafe { (a.clang_visitChildren)(c, tramp::<F>, &mut f as *mut F as P) };
}

/// The paths as Path.resolve gives them (the verbatim prefix of canonicalize dropped).
fn resolve(p: &str) -> String {
    let s = match std::fs::canonicalize(p) {
        Ok(c) => c.to_string_lossy().into_owned(),
        Err(_) => std::path::absolute(p).map(|c| c.to_string_lossy().into_owned()).unwrap_or_else(|_| p.to_string()),
    };
    if let Some(r) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{r}")
    } else if let Some(r) = s.strip_prefix(r"\\?\") {
        r.to_string()
    } else {
        s
    }
}

/// p relative to the resolved root, `/`-separated (Path.relative_to(...).as_posix()); None outside it.
fn rel_to(p: &str, rootr: &str) -> Option<String> {
    let r = std::path::Path::new(p).strip_prefix(rootr).ok()?;
    Some(r.to_string_lossy().replace('\\', "/"))
}

fn chars_of(b: &[u8]) -> usize {
    String::from_utf8_lossy(b).chars().count()
}

// ------------------------------------------------------------------------------------------------ the unit

struct Tu {
    index: P,
    tu: P,
    path: CString,
    path_s: String,
}

unsafe impl Send for Tu {}

impl Drop for Tu {
    fn drop(&mut self) {
        if let Ok(a) = api() {
            unsafe {
                (a.clang_disposeTranslationUnit)(self.tu);
                (a.clang_disposeIndex)(self.index);
            }
        }
    }
}

/// A parsed translation unit (cparse.parse); one user at a time.
pub struct Unit {
    inner: Mutex<Tu>,
}

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::runtime(format!("a NUL in {s:?}")))
}

/// Parse a file (its text handed over) with the arguments, in any thread (each parse has its own index).
pub(crate) fn parse(path: &str, args: &[String], text: &str, preamble: bool) -> Result<Unit, String> {
    let a = LIB.get().map(|l| &l.1).ok_or("libclang is not loaded (cparse.load)")?;
    let cpath = CString::new(path).map_err(|_| format!("a NUL in {path:?}"))?;
    let cargs: Vec<CString> = args.iter().map(|s| CString::new(s.as_str()).map_err(|_| format!("a NUL in {s:?}"))).collect::<Result<_, _>>()?;
    let ctext = text.as_bytes();
    let opts = DETAILED | KEEP_GOING | if preamble { PREAMBLE } else { 0 };
    let argv: Vec<*const c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    let mut un = CXUnsavedFile { name: cpath.as_ptr(), contents: ctext.as_ptr() as *const c_char, length: ctext.len() as c_ulong };
    let (idx, tu) = unsafe {
        let idx = (a.clang_createIndex)(0, 0);
        let tu = (a.clang_parseTranslationUnit)(idx, cpath.as_ptr(), argv.as_ptr(), argv.len() as c_int, &mut un, 1, opts);
        (idx, tu)
    };
    if tu.is_null() {
        unsafe { (a.clang_disposeIndex)(idx) };
        return Err(format!("libclang could not parse {path}"));
    }
    Ok(Unit { inner: Mutex::new(Tu { index: idx, tu, path: cpath, path_s: path.to_string() }) })
}

impl Unit {
    /// Parse again with a new text over the precompiled preamble.
    pub(crate) fn reparse_text(&self, text: &str) -> Result<(), String> {
        let a = LIB.get().map(|l| &l.1).ok_or("libclang is not loaded")?;
        let t = lock(self);
        let ctext = text.as_bytes();
        let mut un = CXUnsavedFile { name: t.path.as_ptr(), contents: ctext.as_ptr() as *const c_char, length: ctext.len() as c_ulong };
        if unsafe { (a.clang_reparseTranslationUnit)(t.tu, 1, &mut un, 0) } != 0 {
            return Err(format!("libclang could not reparse {}", t.path_s));
        }
        Ok(())
    }

    /// Every file the parse read besides the parsed one.
    pub(crate) fn included(&self) -> Result<Vec<String>> {
        Ok(includes(api()?, lock(self).tu))
    }

    /// The model of the unit (root: the project root; text: the parsed text).
    pub(crate) fn model_out(&self, root: &str, text: &str) -> Result<ModelOut> {
        model_rs(api()?, &lock(self), root, text)
    }

    /// The diagnostics of the unit (cparse.diagnostics).
    pub(crate) fn diags(&self, root: &str, text: &str, presumed: bool) -> Result<Vec<CDiag>> {
        diagnostics_rs(api()?, &lock(self), root, text, presumed)
    }
}

#[cfg(test)]
impl Unit {
    /// The identity of the libclang unit (a reparse keeps it, a new parse makes another).
    pub(crate) fn tu_id(&self) -> usize {
        lock(self).tu as usize
    }
}

fn lock(u: &Unit) -> std::sync::MutexGuard<'_, Tu> {
    u.inner.lock().unwrap_or_else(|e| e.into_inner())
}

impl Unit {
    /// cparse.refs of the unit.
    pub(crate) fn refs(&self, root: &str, text: &str, names: Vec<String>) -> Result<Vec<(String, Vec<(usize, usize)>)>> {
        let a = api()?;
        let t = lock(self);
        refs(a, &t, root, text, &names)
    }
}

fn includes(a: &Api, tu: P) -> Vec<String> {
    extern "C" fn v(f: P, _stack: *const CXLoc, depth: c_uint, d: P) {
        if depth > 0 {
            unsafe { (*(d as *mut Vec<P>)).push(f) };
        }
    }
    let mut files: Vec<P> = vec![];
    unsafe { (a.clang_getInclusions)(tu, v, &mut files as *mut Vec<P> as P) };
    files.into_iter().map(|f| take(a, unsafe { (a.clang_getFileName)(f) })).collect()
}

fn diag_list(a: &Api, tu: P) -> Vec<P> {
    let n = unsafe { (a.clang_getNumDiagnostics)(tu) };
    (0..n).map(|i| unsafe { (a.clang_getDiagnostic)(tu, i) }).collect()
}

fn dispose_diags(a: &Api, ds: Vec<P>) {
    for d in ds {
        unsafe { (a.clang_disposeDiagnostic)(d) };
    }
}

// ------------------------------------------------------------------------------------------------ the model

type Pos = (String, i64, i64); // file below root, line, column in characters

/// Maps clang's (file, line, byte column) to the project's positions (cparse.model's where_at).
struct Where<'a> {
    rootr: String,
    main: String,
    main_rel: Option<String>,
    main_lines: Vec<&'a [u8]>,
    files: HashMap<String, (bool, Option<String>)>,
    raw: HashMap<String, (Vec<u8>, Vec<usize>)>, // a header's bytes, its line starts
}

impl<'a> Where<'a> {
    fn new(root: &str, path: &str, text: &'a str) -> Self {
        let rootr = resolve(root);
        let main = resolve(path);
        let main_rel = rel_to(&main, &rootr);
        Where { main_lines: text.as_bytes().split(|&b| b == b'\n').collect(), rootr, main, main_rel, files: HashMap::new(), raw: HashMap::new() }
    }

    fn at(&mut self, f: &str, line: u32, col: u32) -> Option<Pos> {
        if !self.files.contains_key(f) {
            let p = resolve(f);
            let r = rel_to(&p, &self.rootr);
            self.files.insert(f.to_string(), (p == self.main, r));
        }
        let (is_main, rel) = &self.files[f];
        let li = line as usize;
        let cut = |b: &[u8]| (chars_of(&b[..b.len().min((col as usize).saturating_sub(1))]) + 1) as i64;
        if *is_main {
            let r = self.main_rel.clone()?;
            let b: &[u8] = if li > 0 && li <= self.main_lines.len() { self.main_lines[li - 1] } else { b"" };
            return Some((r, line as i64, cut(b)));
        }
        let r = rel.clone()?;
        let (data, starts) = self.raw.entry(f.to_string()).or_insert_with(|| {
            let d = std::fs::read(f).unwrap_or_default();
            let s = std::iter::once(0).chain(memchr::memchr_iter(b'\n', &d).map(|i| i + 1)).collect();
            (d, s)
        });
        let b: &[u8] = if li > 0 && li <= starts.len() {
            let s = starts[li - 1];
            let e = starts.get(li).map(|&e| e - 1).unwrap_or(data.len());
            &data[s..e]
        } else {
            b""
        };
        Some((r, line as i64, cut(b)))
    }

    fn loc(&mut self, a: &Api, loc: CXLoc) -> Option<Pos> {
        let (f, line, col) = expand(a, loc);
        self.at(&f?, line, col)
    }
}

/// What the scan reads of one project file of a parse (Unit.model's entry; the fields as its docstring says).
#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileModel {
    pub defs: Vec<(i64, i64, String, bool)>,
    pub vars: Vec<(i64, i64, i64, i64, String, String, bool, i64)>, // .., the size of its type (0: none clang knows)
    pub macros: Vec<(i64, String, bool)>,
    pub defines: Vec<(String, bool, i64, i64, i64, i64)>,
    pub casts: Vec<(i64, i64, i64, i64, String)>,
    pub comments: Vec<(i64, i64, i64, i64)>,
    pub strings: Vec<(i64, i64, i64, i64)>,
    pub decls: Vec<Decl>,
    pub types: Vec<(i64, String)>,
    pub dead: Vec<(i64, i64)>,
    #[serde(default)]
    pub arrays: Vec<(String, i64)>, // (name, element size) of each array variable declared in the file
}

/// A parse's model: every project file it holds (in the order the parse met them), the files it read, whether an
/// include was not found.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelOut {
    pub files: Vec<(String, FileModel)>,
    pub deps: Vec<String>,
    pub missing: bool,
}

pub type Lc = (i64, i64);

/// ("f", name, static, start, name position, end, body start, K&R parameters) / ("v", name, static, start, name
/// position, end, kind, initialised, aggregate).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum Decl {
    F(String, bool, Lc, Lc, Option<Lc>, Option<Lc>, Option<Vec<(String, Option<String>)>>),
    V(String, bool, Lc, Lc, Lc, String, bool, Option<bool>),
}

struct Files {
    order: Vec<String>,
    by: HashMap<String, FileModel>,
}

impl Files {
    fn entry(&mut self, rel: &str) -> &mut FileModel {
        if !self.by.contains_key(rel) {
            self.order.push(rel.to_string());
        }
        self.by.entry(rel.to_string()).or_default()
    }
}

fn lc(p: &Pos) -> Lc {
    (p.1, p.2)
}

fn promoted(k: c_int) -> Option<String> {
    match k {
        4 | 5 | 8 | 13 | 14 | 16 => Some("int".into()), // char, unsigned char, unsigned short, char, signed char, short
        21 => Some("double".into()),                    // float
        _ => None,
    }
}

static CAST_END: LazyLock<BRegex> = LazyLock::new(|| BRegex::new(r"[()][ \t\r\n]*((?:0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*)").unwrap());

/// cparse._casts: (start, literal end, literal) byte offsets of every integer literal cast to a pointer type.
fn casts_of(a: &Api, tu: P, f: P, data: &[u8]) -> Vec<(usize, usize, String)> {
    let mut out = vec![];
    let mut from = 0;
    while let Some(m) = CAST_END.captures_at(data, from) {
        let all = m.get(0).unwrap();
        let lit = m.get(1).unwrap();
        // (?![\w.]) after the literal
        if data.get(all.end()).is_some_and(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.') {
            from = all.start() + 1;
            continue;
        }
        from = all.end();
        let mut j = all.start() as isize;
        while j >= 0 {
            let ch = data[j as usize];
            if matches!(ch, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) || ch == b'(' {
                j -= 1;
                continue;
            }
            if ch != b')' {
                break;
            }
            let c = unsafe { (a.clang_getCursor)(tu, (a.clang_getLocationForOffset)(tu, f, j as c_uint)) };
            if is_null(a, c) || unsafe { (a.clang_getCursorKind)(c) } != CSTYLE_CAST_EXPR {
                break;
            }
            let (mut k, mut depth) = (j, 0i32);
            while k >= 0 {
                depth += (data[k as usize] == b')') as i32 - (data[k as usize] == b'(') as i32;
                if depth == 0 {
                    break;
                }
                k -= 1;
            }
            if k < 0 {
                break;
            }
            if unsafe { (a.clang_getCanonicalType)((a.clang_getCursorType)(c)) }.kind == T_POINTER {
                out.push((k as usize, all.end(), String::from_utf8_lossy(lit.as_bytes()).into_owned()));
                break;
            }
            j = k - 1;
        }
    }
    out
}

/// (comments, string and character literals) of a file the unit read, as (start, end) byte offsets of its text
/// (data): clang_tokenize over the whole file, a dead branch too; a literal from its quote (an `L` before it is
/// code).
fn lex(a: &Api, tu: P, f: P, data: &[u8]) -> (Vec<(usize, usize)>, Vec<(usize, usize)>) {
    let (mut comments, mut strings) = (vec![], vec![]);
    if f.is_null() {
        return (comments, strings);
    }
    let r = unsafe { (a.clang_getRange)((a.clang_getLocationForOffset)(tu, f, 0), (a.clang_getLocationForOffset)(tu, f, data.len() as c_uint)) };
    let (mut toks, mut n): (*mut CXToken, c_uint) = (std::ptr::null_mut(), 0);
    unsafe { (a.clang_tokenize)(tu, r, &mut toks, &mut n) };
    let off = |l: CXLoc| {
        let (mut f, mut x, mut y, mut o): (P, c_uint, c_uint, c_uint) = (std::ptr::null_mut(), 0, 0, 0);
        unsafe { (a.clang_getFileLocation)(l, &mut f, &mut x, &mut y, &mut o) };
        (o as usize).min(data.len())
    };
    for i in 0..n as usize {
        let k = unsafe { *toks.add(i) };
        let kind = unsafe { (a.clang_getTokenKind)(k) };
        if kind != TOKEN_COMMENT && kind != TOKEN_LITERAL {
            continue;
        }
        let e = unsafe { (a.clang_getTokenExtent)(tu, k) };
        let (s, end) = (off(unsafe { (a.clang_getRangeStart)(e) }), off(unsafe { (a.clang_getRangeEnd)(e) }));
        if kind == TOKEN_COMMENT {
            comments.push((s, end));
        } else if let Some(q) = data[s..end].iter().position(|&c| c == b'"' || c == b'\'') {
            if data[s..s + q].iter().all(|c| c.is_ascii_alphanumeric()) {
                strings.push((s + q, end));
            }
        }
    }
    if !toks.is_null() {
        unsafe { (a.clang_disposeTokens)(tu, toks, n) };
    }
    (comments, strings)
}

/// (line, column in characters) of byte offsets of a text, both from 1.
fn line_col(data: &[u8], nl: &[usize], off: usize) -> Lc {
    let line = nl.partition_point(|&x| x < off) + 1;
    let bol = if line > 1 { nl[line - 2] + 1 } else { 0 };
    (line as i64, (chars_of(&data[bol..off]) + 1) as i64)
}

fn model_rs(a: &Api, t: &Tu, root: &str, text: &str) -> Result<ModelOut> {
    let tu = t.tu;
    let mut w = Where::new(root, &t.path_s, text);
    let mut out = Files { order: vec![], by: HashMap::new() };
    let diags = diag_list(a, tu);
    let mut errors: Option<HashSet<(String, i64)>> = None;
    let mut enum_at: Option<Pos> = None;
    let mut recs: Vec<CXCursor> = vec![];
    visit(a, unsafe { (a.clang_getTranslationUnitCursor)(tu) }, |c| {
        recs.push(c);
        CONTINUE
    });
    for c in recs {
        let k = unsafe { (a.clang_getCursorKind)(c) };
        if k == FUNCTION_DECL {
            if unsafe { (a.clang_Cursor_isFunctionInlined)(c) } != 0 {
                continue;
            }
            let name = spelling(a, c);
            let ext = unsafe { (a.clang_getCursorExtent)(c) };
            let stat = unsafe { (a.clang_Cursor_getStorageClass)(c) } == SC_STATIC;
            let def = unsafe { (a.clang_isCursorDefinition)(c) } != 0;
            let ws = w.loc(a, unsafe { (a.clang_getRangeStart)(ext) });
            let n = w.loc(a, unsafe { (a.clang_getCursorLocation)(c) });
            let e = w.loc(a, unsafe { (a.clang_getRangeEnd)(ext) });
            let mut body: Option<CXCursor> = None;
            visit(a, c, |x| {
                if unsafe { (a.clang_getCursorKind)(x) } == COMPOUND_STMT {
                    body = Some(x);
                    BREAK
                } else {
                    CONTINUE
                }
            });
            let (b, knr) = match body {
                Some(bc) => {
                    let b = w.loc(a, unsafe { (a.clang_getRangeStart)((a.clang_getCursorExtent)(bc)) });
                    let n = unsafe { (a.clang_Cursor_getNumArguments)(c) }.max(0) as c_uint;
                    let ps = (0..n)
                        .map(|i| {
                            let arg = unsafe { (a.clang_Cursor_getArgument)(c, i) };
                            let k = unsafe { (a.clang_getCanonicalType)((a.clang_getCursorType)(arg)) }.kind;
                            (spelling(a, arg), promoted(k))
                        })
                        .collect();
                    (b, Some(ps))
                }
                None => (None, None),
            };
            let (Some(ws), Some(n)) = (ws, n) else { continue };
            if ws.0 != n.0 {
                continue;
            }
            let e = e.filter(|e| e.0 == ws.0); // a body that ends in an included file: no end here
            let f = out.entry(&ws.0);
            f.decls.push(Decl::F(name.clone(), stat, lc(&ws), lc(&n), e.as_ref().map(lc), b.as_ref().map(lc), knr));
            if def {
                f.defs.push((ws.1, ws.2, name, stat));
            }
        } else if k == VAR_DECL {
            let name = spelling(a, c);
            let ext = unsafe { (a.clang_getCursorExtent)(c) };
            let sc = unsafe { (a.clang_Cursor_getStorageClass)(c) };
            let ty = unsafe { (a.clang_getCanonicalType)((a.clang_getCursorType)(c)) };
            let tk = ty.kind;
            let kind = if unsafe { (a.clang_isCursorDefinition)(c) } != 0 || sc != SC_EXTERN { "def" } else { "extern" };
            let ws = w.loc(a, unsafe { (a.clang_getRangeStart)(ext) });
            let n = w.loc(a, unsafe { (a.clang_getCursorLocation)(c) });
            let e = w.loc(a, unsafe { (a.clang_getRangeEnd)(ext) });
            let mut init = false;
            visit(a, c, |x| {
                if unsafe { (a.clang_isExpression)((a.clang_getCursorKind)(x)) } != 0 {
                    init = true;
                    BREAK
                } else {
                    CONTINUE
                }
            });
            let aggregate = matches!(tk, 112 | 114 | 115) || tk == T_RECORD; // constant / incomplete / variable array
            let (Some(ws), Some(n), Some(e)) = (ws, n, e) else { continue };
            if !(ws.0 == n.0 && n.0 == e.0) {
                continue;
            }
            let stat = sc == SC_STATIC;
            let errs = errors.get_or_insert_with(|| {
                diags
                    .iter()
                    .filter(|&&d| unsafe { (a.clang_getDiagnosticSeverity)(d) } >= SEV_ERROR)
                    .filter_map(|&d| w.loc(a, unsafe { (a.clang_getDiagnosticLocation)(d) }).map(|p| (p.0, p.1)))
                    .collect()
            });
            // None: a type clang does not know (its recovery makes an unknown type name int)
            let agg = if (ws.1..=e.1).any(|ln| errs.contains(&(ws.0.clone(), ln))) { None } else { Some(aggregate) };
            let f = out.entry(&ws.0);
            // the type's size (an incomplete or erroneous type has none: clang's recovery makes an unknown type int)
            let size = if agg.is_some() { unsafe { (a.clang_Type_getSizeOf)(ty) }.max(0) } else { 0 };
            f.vars.push((ws.1, ws.2, e.1, e.2, name.clone(), kind.to_string(), stat, size));
            if matches!(tk, 112 | 114) {
                let size = unsafe { (a.clang_Type_getSizeOf)((a.clang_getArrayElementType)(ty)) };
                if size > 0 {
                    f.arrays.push((name.clone(), size));
                }
            }
            f.decls.push(Decl::V(name, stat, lc(&ws), lc(&n), lc(&e), kind.to_string(), init, agg));
        } else if k == TYPEDEF_DECL || ((k == STRUCT_DECL || k == UNION_DECL || k == ENUM_DECL) && unsafe { (a.clang_isCursorDefinition)(c) } != 0) {
            let name = spelling(a, c);
            if k != TYPEDEF_DECL && name.is_empty() {
                continue;
            }
            let n = w.loc(a, unsafe { (a.clang_getCursorLocation)(c) });
            if let Some(n) = &n {
                if !(name.starts_with("struct (") || name.starts_with("union (") || name.starts_with("enum (")) {
                    out.entry(&n.0).types.push((n.1, name));
                }
            }
            enum_at = if k == ENUM_DECL { n } else { None };
            if k == ENUM_DECL {
                let mut consts = vec![];
                visit(a, c, |x| {
                    if unsafe { (a.clang_getCursorKind)(x) } == ENUM_CONSTANT_DECL {
                        consts.push(x);
                    }
                    CONTINUE
                });
                if enum_at.is_some() {
                    for x in consts {
                        if let Some(xn) = w.loc(a, unsafe { (a.clang_getCursorLocation)(x) }) {
                            out.entry(&xn.0).types.push((xn.1, spelling(a, x)));
                        }
                    }
                }
            }
        } else if k == MACRO_DEFINITION {
            if let Some(p) = w.loc(a, unsafe { (a.clang_getCursorLocation)(c) }) {
                let fl = unsafe { (a.clang_Cursor_isMacroFunctionLike)(c) } != 0;
                let name = spelling(a, c);
                // the definition's extent: from its name to the end of its last token
                let e = w.loc(a, unsafe { (a.clang_getRangeEnd)((a.clang_getCursorExtent)(c)) }).filter(|e| e.0 == p.0);
                let f = out.entry(&p.0);
                if let Some(e) = e {
                    f.defines.push((name.clone(), fl, p.1, p.2, e.1, e.2));
                }
                f.macros.push((p.1, name, fl));
            }
        }
    }
    let deps: Vec<String> = includes(a, tu).iter().map(|f| resolve(f)).collect::<BTreeSet<_>>().into_iter().collect();
    // a file's casts and dead ranges, mapped by the file's own lines
    let file_parts = |w: &mut Where, out: &mut Files, fname: &str, data: &[u8], rel: Option<&str>| -> Result<()> {
        let cf = cstr(fname)?;
        let f = unsafe { (a.clang_getFile)(tu, cf.as_ptr()) };
        let found = casts_of(a, tu, f, data);
        if let Some(r) = rel {
            let nl: Vec<usize> = memchr::memchr_iter(b'\n', data).collect();
            let span = |(s, e): (usize, usize)| {
                let (wl, wc) = line_col(data, &nl, s);
                let (el, ec) = line_col(data, &nl, e);
                (wl, wc, el, ec)
            };
            let (comments, strings) = lex(a, tu, f, data);
            let m = out.entry(r);
            for (s, e, lit) in found {
                let (wl, wc, el, ec) = span((s, e));
                m.casts.push((wl, wc, el, ec, lit));
            }
            m.comments = comments.into_iter().map(span).collect();
            m.strings = strings.into_iter().map(span).collect();
        }
        let list = unsafe { (a.clang_getSkippedRanges)(tu, f) };
        if !list.is_null() {
            let l = unsafe { &*list };
            for i in 0..l.count as usize {
                let r = unsafe { *l.ranges.add(i) };
                let s = w.loc(a, unsafe { (a.clang_getRangeStart)(r) });
                let e = w.loc(a, unsafe { (a.clang_getRangeEnd)(r) });
                if let (Some(s), Some(e)) = (s, e) {
                    if s.0 == e.0 {
                        out.entry(&s.0).dead.push((s.1, e.1));
                    }
                }
            }
            unsafe { (a.clang_disposeSourceRangeList)(list) };
        }
        Ok(())
    };
    // every project file the parse read holds its entry, an empty one too: the unit holds it
    for d in &deps {
        if let Some(r) = rel_to(d, &w.rootr) {
            out.entry(&r);
            let data = std::fs::read(d).unwrap_or_default();
            file_parts(&mut w, &mut out, d, &data, Some(&r))?;
        }
    }
    let main_rel = w.main_rel.clone();
    if let Some(r) = &main_rel {
        out.entry(r);
    }
    let path = t.path_s.clone();
    file_parts(&mut w, &mut out, &path, text.as_bytes(), main_rel.as_deref())?;
    // an include clang did not find: the file may appear later without the text changing, no result to keep
    let missing = diags.iter().any(|&d| unsafe { (a.clang_getDiagnosticSeverity)(d) } == SEV_FATAL
        && take(a, unsafe { (a.clang_getDiagnosticSpelling)(d) }).contains("not found"));
    dispose_diags(a, diags);
    let files = out.order.iter().map(|r| (r.clone(), out.by.remove(r).unwrap_or_default())).collect();
    Ok(ModelOut { files, deps, missing })
}

 
// ------------------------------------------------------------------------------------------------ diagnostics

static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"'(?:(?:struct|union|enum) )?([A-Za-z_]\w*)'").unwrap());
static IDENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*$").unwrap());
static LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^[ \t]*#[ \t]*line[ \t]+(\d+)(?:[ \t]+"((?:\\.|[^"\\])*)")?"#).unwrap());
const C_WORDS: [&str; 12] = ["struct", "union", "enum", "int", "char", "short", "long", "void", "unsigned", "signed", "float", "double"];

/// cparse.rel: f relative to root when it is inside it, else as clang names it (`/`-separated).
fn rel(rootr: &str, root: &str, f: &str) -> String {
    let p = std::path::Path::new(f);
    let full = if p.is_absolute() { f.to_string() } else { std::path::Path::new(root).join(p).to_string_lossy().into_owned() };
    rel_to(&resolve(&full), rootr).unwrap_or_else(|| f.replace('\\', "/"))
}

/// The symbol at a location: the cursor's spelling when it is an identifier, else the identifier token there.
fn name_at(a: &Api, tu: P, loc: CXLoc) -> Option<String> {
    if expand(a, loc).0.is_none() {
        return None;
    }
    let c = unsafe { (a.clang_getCursor)(tu, loc) };
    if !is_null(a, c) {
        let s = spelling(a, c);
        if IDENT.is_match(&s) {
            return Some(s);
        }
    }
    let (mut toks, mut n): (*mut CXToken, c_uint) = (std::ptr::null_mut(), 0);
    unsafe { (a.clang_tokenize)(tu, (a.clang_getRange)(loc, loc), &mut toks, &mut n) };
    let mut out = None;
    for i in 0..n as usize {
        let t = unsafe { *toks.add(i) };
        if unsafe { (a.clang_getTokenKind)(t) } == TOKEN_IDENTIFIER && unsafe { (a.clang_equalLocations)((a.clang_getTokenLocation)(tu, t), loc) } != 0 {
            out = Some(take(a, unsafe { (a.clang_getTokenSpelling)(tu, t) }));
            break;
        }
    }
    if !toks.is_null() {
        unsafe { (a.clang_disposeTokens)(tu, toks, n) };
    }
    out
}

fn name_of(a: &Api, tu: P, msg: &str, loc: CXLoc) -> Option<String> {
    for m in QUOTED.captures_iter(msg) {
        let s = m.get(1).unwrap().as_str();
        if !C_WORDS.contains(&s) {
            return Some(s.to_string());
        }
    }
    name_at(a, tu, loc)
}

/// The `#line` directives of a text: (their physical lines, (file, number) after each), the file itself first.
fn line_map(text: &str, name: &str) -> (Vec<usize>, Vec<(String, usize)>) {
    let (mut lines, mut at) = (vec![0usize], vec![(name.to_string(), 1usize)]);
    let (mut ln, mut pos) = (1usize, 0usize);
    for m in LINE.captures_iter(text) {
        let s = m.get(0).unwrap().start();
        let f = match m.get(2) {
            Some(g) => g.as_str().replace("\\\\", "\\"),
            None => at.last().unwrap().0.clone(),
        };
        ln += memchr::memchr_iter(b'\n', &text.as_bytes()[pos..s]).count();
        pos = s;
        lines.push(ln);
        at.push((f, m[1].parse().unwrap_or(0)));
    }
    (lines, at)
}

fn locate(lmap: &(Vec<usize>, Vec<(String, usize)>), line: usize) -> (String, i64) {
    let k = lmap.0.partition_point(|&x| x < line) - 1; // the last directive above the line
    let (f, n) = &lmap.1[k];
    (f.clone(), *n as i64 + line as i64 - lmap.0[k] as i64 - 1)
}

/// One diagnostic of a parse (cparse.diagnostics' dict): its file (relative to root when inside it), line, kind
/// (error / warning / note), message, warning option and the name it is about.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CDiag {
    pub file: String,
    pub line: i64,
    pub kind: String,
    pub msg: String,
    #[serde(default)]
    pub flag: String,
    #[serde(default)]
    pub name: Option<String>,
}

fn diagnostics_rs(a: &Api, t: &Tu, root: &str, text: &str, presumed: bool) -> Result<Vec<CDiag>> {
    let tu = t.tu;
    let rootr = resolve(root);
    let main = resolve(&t.path_s);
    let lmap = presumed.then(|| line_map(text, &t.path_s));
    let mut files: HashMap<String, (bool, String)> = HashMap::new();
    let mut out: Vec<CDiag> = vec![];
    let mut one = |d: P, kind: &str| -> Result<bool> {
        let loc = unsafe { (a.clang_getDiagnosticLocation)(d) };
        let (f, line, _) = expand(a, loc);
        let Some(f) = f else { return Ok(false) }; // no location (the command line)
        let (is_main, fr) = files.entry(f.clone()).or_insert_with(|| (resolve(&f) == main, rel(&rootr, root, &f))).clone();
        let (mut fr, mut line) = (fr, line as i64);
        if is_main {
            if let Some(lm) = &lmap {
                let (mf, l) = locate(lm, line as usize);
                fr = rel(&rootr, root, &mf);
                line = l;
            }
        }
        let msg = take(a, unsafe { (a.clang_getDiagnosticSpelling)(d) });
        let flag = take(a, unsafe { (a.clang_getDiagnosticOption)(d, std::ptr::null_mut()) });
        let name = name_of(a, tu, &msg, loc);
        out.push(CDiag { file: fr, line, kind: kind.to_string(), msg, flag, name });
        Ok(true)
    };
    let diags = diag_list(a, tu);
    for &d in &diags {
        let sev = unsafe { (a.clang_getDiagnosticSeverity)(d) };
        if sev < SEV_WARNING {
            continue;
        }
        if !one(d, if sev == SEV_WARNING { "warning" } else { "error" })? {
            continue;
        }
        let set = unsafe { (a.clang_getChildDiagnostics)(d) };
        if set.is_null() {
            continue;
        }
        for i in 0..unsafe { (a.clang_getNumDiagnosticsInSet)(set) } {
            let n = unsafe { (a.clang_getDiagnosticInSet)(set, i) };
            if !take(a, unsafe { (a.clang_getDiagnosticSpelling)(n) }).starts_with("in file included from") {
                one(n, "note")?;
            }
        }
    }
    dispose_diags(a, diags);
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ refs

fn refs(a: &Api, t: &Tu, root: &str, text: &str, names: &[String]) -> Result<Vec<(String, Vec<(usize, usize)>)>> {
    let tu = t.tu;
    let rootr = resolve(root);
    let main = resolve(&t.path_s);
    let pat = BRegex::new(&format!(r"(?-u)\b(?:{})\b", names.iter().map(|n| regex::escape(n)).collect::<Vec<_>>().join("|")))
        .map_err(|e| Error::runtime(e.to_string()))?;
    let mut files: Vec<(String, String, Vec<u8>, Option<String>)> = vec![(t.path_s.clone(), main.clone(), text.as_bytes().to_vec(), rel_to(&main, &rootr))];
    for i in includes(a, tu) {
        let p = resolve(&i);
        if rel_to(&p, &rootr).is_some() && files.iter().all(|f| f.1 != p) {
            let data = std::fs::read(&p).unwrap_or_default();
            let r = rel_to(&p, &rootr);
            files.push((p.clone(), p, data, r));
        }
    }
    let mut out: Vec<(String, Vec<(usize, usize)>)> = vec![];
    for (fname, _, data, r) in &files {
        let cf = cstr(fname)?;
        let f = unsafe { (a.clang_getFile)(tu, cf.as_ptr()) };
        let mut nl: Option<Vec<usize>> = None;
        for m in pat.find_iter(data) {
            let c = unsafe { (a.clang_getCursor)(tu, (a.clang_getLocationForOffset)(tu, f, m.start() as c_uint)) };
            if is_null(a, c) {
                continue;
            }
            let rf = unsafe { (a.clang_getCursorReferenced)(c) };
            let t = if is_null(a, rf) { c } else { rf };
            if spelling(a, t).as_bytes() != m.as_bytes() {
                continue;
            }
            let k = unsafe { (a.clang_getCursorKind)(t) };
            let local = matches!(k, PARM_DECL | FIELD_DECL | LABEL_STMT)
                || (k == VAR_DECL && {
                    let p = unsafe { (a.clang_getCursorSemanticParent)(t) };
                    !is_null(a, p) && unsafe { (a.clang_getCursorKind)(p) } != TRANSLATION_UNIT
                });
            if !local {
                continue;
            }
            let nl = nl.get_or_insert_with(|| memchr::memchr_iter(b'\n', data).collect());
            let (line, col) = line_col(data, nl, m.start());
            if let Some(r) = r {
                match out.iter_mut().find(|x| &x.0 == r) {
                    Some(x) => x.1.push((line as usize, col as usize)),
                    None => out.push((r.clone(), vec![(line as usize, col as usize)])),
                }
            }
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ system headers

/// cparse.function_headers: name -> the header (lower case) of every C-calling-convention function the system
/// headers declare, parsed as one unit that includes `headers` in their order of preference.
pub fn clang_function_headers(args: Vec<String>, headers: Vec<String>) -> Result<Vec<(String, String)>> {
    let a = api()?;
    let text: String = headers.iter().map(|h| format!("#include <{h}>\n")).collect();
    let name = "dcp_system_headers.c";
    let u = {
        let cpath = cstr(name)?;
        let cargs: Vec<CString> = args.iter().map(|s| cstr(s)).collect::<Result<_>>()?;
        let argv: Vec<*const c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
        let mut un = CXUnsavedFile { name: cpath.as_ptr(), contents: text.as_ptr() as *const c_char, length: text.len() as c_ulong };
        unsafe {
            let idx = (a.clang_createIndex)(0, 0);
            let tu = (a.clang_parseTranslationUnit)(idx, cpath.as_ptr(), argv.as_ptr(), argv.len() as c_int, &mut un, 1, KEEP_GOING);
            if tu.is_null() {
                (a.clang_disposeIndex)(idx);
                return Err(Error::runtime("libclang could not parse the system headers"));
            }
            Tu { index: idx, tu, path: cpath, path_s: name.to_string() }
        }
    };
    let order: HashMap<String, usize> = headers.iter().enumerate().map(|(k, h)| (h.to_lowercase(), k)).collect();
    let rank = |h: &str| order.get(h).copied().unwrap_or(order.len());
    let mut out: Vec<(String, String)> = vec![];
    let mut at: HashMap<String, usize> = HashMap::new();
    visit(a, unsafe { (a.clang_getTranslationUnitCursor)(u.tu) }, |c| {
        if unsafe { (a.clang_getCursorKind)(c) } == FUNCTION_DECL {
            let (f, _, _) = expand(a, unsafe { (a.clang_getCursorLocation)(c) });
            if let Some(f) = f {
                if unsafe { (a.clang_getFunctionTypeCallingConv)((a.clang_getCursorType)(c)) } == CC_C {
                    let h = std::path::Path::new(&f).file_name().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
                    let s = spelling(a, c);
                    match at.get(&s) {
                        None => {
                            at.insert(s.clone(), out.len());
                            out.push((s, h));
                        }
                        Some(&i) if rank(&h) < rank(&out[i].1) => out[i].1 = h,
                        _ => {}
                    }
                }
            }
        }
        CONTINUE
    });
    Ok(out)
}
