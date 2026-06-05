// =============================================================================
//  xways-trufflehog — TruffleHog secret scanner for X-Ways Forensics 21.7+
//
//  Per-item wrap of trufflesecurity/trufflehog v3.x. For each file in the
//  active volume snapshot (or a Directory-Browser-Context selection), the
//  X-Tension extracts the bytes via XWF_Read to a scratch file under the
//  evidence working directory, invokes `trufflehog filesystem --json <file>`,
//  parses the JSONL output, and tags items in a Report Table.
//
//  GUI architecture (mirrors xways-ual-timeliner / xways-updater):
//    XT_Prepare (non-DBC) -> ShowDialog -> user clicks Run -> worker thread
//      iterates items, posts WM_APP_* progress to dialog, returns -> dialog
//      stays open with summary -> user closes.
//    XT_Prepare (DBC) -> request XT_ProcessItem callbacks to collect IDs ->
//      XT_Finalize -> ShowDialog with the collected selection.
//
//  Dialog: .rc-based DIALOGEX (resource.h / xways-trufflehog.rc) following
//  docs/xtension-dialog-conventions.md. Settings round-trip via a `Settings`
//  struct passed via LPARAM.
//
//  Authoritative API: references/api/XWF_API-source-2024-05-31/src/X-Tension.h
// =============================================================================

#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <commdlg.h>
#include <commctrl.h>
#include <process.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <atomic>

#include "resource.h"

// --- Identity ---------------------------------------------------------------
static const wchar_t* NAME         = L"xways-trufflehog";
static const wchar_t* VERSION      = L"0.1.0";
static const wchar_t* DESCRIPTION  = L"TruffleHog secret scanner wrapper for X-Ways Forensics.";
static const wchar_t* REPORT_TABLE = L"trufflehog: secrets found";

// --- Logging ---------------------------------------------------------------
//   Default-on during development; flipped by Settings.verbose (cfg key
//   `xtension_verbose` and the Verbose checkbox in the dialog).
static bool g_verbose = true;

// --- XT_Prepare nOpType ----------------------------------------------------
enum : DWORD {
    XT_ACTION_RUN = 0,
    XT_ACTION_RVS = 1,
    XT_ACTION_LSS = 2,
    XT_ACTION_PSS = 3,
    XT_ACTION_DBC = 4,
    XT_ACTION_SHC = 5,
};

enum : DWORD { COMMENT_REPLACE = 0, COMMENT_APPEND = 1, COMMENT_PREPEND = 2 };

// --- Dialog message IDs (worker -> dialog) ---------------------------------
#define WM_APP_PROGRESS   (WM_APP + 1)  // wp = permille (0..1000)
#define WM_APP_STATUS     (WM_APP + 2)  // lp = heap-allocated wchar_t* (dialog owns + deletes)
#define WM_APP_DONE       (WM_APP + 3)  // wp = success bool
#define WM_APP_MARQUEE    (WM_APP + 4)  // wp = 1 start marquee, 0 stop
#define WM_APP_VERSION    (WM_APP + 5)  // lp = heap-allocated std::wstring* (dialog owns + deletes)

// --- XWF_* typedefs --------------------------------------------------------
typedef VOID   (__stdcall *pfn_XWF_OutputMessage)(const wchar_t*, DWORD);
typedef const wchar_t* (__stdcall *pfn_XWF_GetItemName)(LONG);
typedef INT64  (__stdcall *pfn_XWF_GetItemSize)(LONG);
typedef VOID   (__stdcall *pfn_XWF_GetVolumeName)(HANDLE, wchar_t*, DWORD);
typedef BOOL   (__stdcall *pfn_XWF_AddToReportTable)(LONG, const wchar_t*, DWORD);
typedef BOOL   (__stdcall *pfn_XWF_Label)(LONG, const wchar_t*, DWORD);
typedef BOOL   (__stdcall *pfn_XWF_AddComment)(LONG, const wchar_t*, DWORD);
typedef INT64  (__stdcall *pfn_XWF_GetEvObjProp)(HANDLE, DWORD, PVOID);
typedef DWORD  (__stdcall *pfn_XWF_Read)(HANDLE, INT64, BYTE*, DWORD);
typedef HANDLE (__stdcall *pfn_XWF_OpenItem)(HANDLE, LONG, DWORD);
typedef VOID   (__stdcall *pfn_XWF_Close)(HANDLE);
typedef DWORD  (__stdcall *pfn_XWF_GetItemCount)(LPVOID);
typedef LONG   (__stdcall *pfn_XWF_GetItemInformation)(LONG, LONG, BOOL*);
typedef LONG   (__stdcall *pfn_XWF_GetItemParent)(LONG);
typedef INT64  (__stdcall *pfn_XWF_GetCaseProp)(LPVOID, LONG, PVOID, LONG);
typedef INT64  (__stdcall *pfn_XWF_GetVSProp)(LONG, PVOID);
typedef BOOL   (__stdcall *pfn_XWF_GetHashValue)(LONG, LPVOID);
typedef BOOL   (__stdcall *pfn_XWF_ShouldStop)();

static pfn_XWF_OutputMessage      XWF_OutputMessage      = nullptr;
static pfn_XWF_GetItemName        XWF_GetItemName        = nullptr;
static pfn_XWF_GetItemSize        XWF_GetItemSize        = nullptr;
static pfn_XWF_GetVolumeName      XWF_GetVolumeName      = nullptr;
static pfn_XWF_AddToReportTable   XWF_AddToReportTable   = nullptr;
static pfn_XWF_Label              XWF_Label              = nullptr;
static pfn_XWF_AddComment         XWF_AddComment         = nullptr;
static pfn_XWF_GetEvObjProp       XWF_GetEvObjProp       = nullptr;
static pfn_XWF_Read               XWF_Read               = nullptr;
static pfn_XWF_OpenItem           XWF_OpenItem           = nullptr;
static pfn_XWF_Close              XWF_Close              = nullptr;
static pfn_XWF_GetItemCount       XWF_GetItemCount       = nullptr;
static pfn_XWF_GetItemInformation XWF_GetItemInformation = nullptr;
static pfn_XWF_GetItemParent      XWF_GetItemParent      = nullptr;
static pfn_XWF_GetCaseProp        XWF_GetCaseProp        = nullptr;
static pfn_XWF_GetVSProp          XWF_GetVSProp          = nullptr;
static pfn_XWF_GetHashValue       XWF_GetHashValue       = nullptr;
static pfn_XWF_ShouldStop         XWF_ShouldStop         = nullptr;

// XWF_ITEM_INFO_FLAGS / FLAG_DIRECTORY per docs/xways-itemtype-metadata-text.md
// (empirical, cross-checked against xwf-api-rs ItemInfoFlags). 0x02 is
// HasChildObjects, NOT IsDirectory — getting these wrong silently neuters the
// "skip directories" check.
static constexpr LONG XWF_ITEM_INFO_FLAGS         = 3;
static constexpr LONG XWF_ITEM_INFO_FLAG_DIRECTORY = 0x00000001;

// XWF_GetVSProp property: primary hash type configured on the volume
// snapshot. Returns the hash-type enum (see HashTypeToSize below).
static constexpr LONG XWF_VSPROP_HASHTYPE1 = 20;

// XWF_GetHashValue flags written into the first DWORD of the buffer.
static constexpr DWORD XWF_GETHASH_PRIMARY = 0x01;

// X-Ways hash-type enum -> stored size in bytes. Empirical table mirrors
// references/community/xwf-api-rs/.../volume.rs HashType::size().
// Returns 0 for unknown types -- dedup silently no-ops in that case.
static DWORD HashTypeToSize(INT64 hashType) {
    switch (hashType) {
        case 0:  return 1;   // CS8
        case 1:  return 2;   // CS16
        case 2:  return 4;   // CS32
        case 3:  return 8;   // CS64
        case 4:  return 2;   // CRC16
        case 5:  return 4;   // CRC32
        case 6:  return 16;  // MD5
        case 7:  return 16;  // MD4
        case 8:  return 20;  // SHA-1
        case 9:  return 32;  // SHA-256
        case 10: return 16;  // RIPEMD-128
        case 11: return 20;  // RIPEMD-160
        case 12: return 16;  // ED2K
        case 13: return 4;   // Adler32
        case 14: return 16;  // Tiger-128
        case 15: return 20;  // Tiger-160
        case 16: return 24;  // Tiger-192
        case 17: return 24;  // TigerTreeHash
        case 18: return 16;  // MD5Folded
        default: return 0;
    }
}

// Query the primary hash bytes for an item. Returns empty string if no
// hash is stored for the item, X-Ways doesn't support hash retrieval, or
// hashSize is 0 (unknown hash type). Result bytes are suitable as a
// std::map key for cross-item dedup.
//
// Buffer layout per X-Ways API:
//   offset 0 (DWORD): caller-provided flags (0x01 = primary hash)
//   on return: X-Ways overwrites buffer starting at offset 0 with the
//   raw hash bytes (length = hashSize).
//
// Sentinel trick: some X-Ways versions return TRUE without actually
// overwriting the buffer (observed when the snapshot has a hash type
// configured but per-item hashes have NOT been computed -- a fresh case
// where the analyst hasn't run "Compute hash" yet). Without detection,
// every item appears to have the SAME hash {0x01, 0x00, ..., 0x00} (our
// flag DWORD + the zero-init padding) and every item dedup-collides to
// whatever findings were last cached -- catastrophic false-tagging.
//
// We pre-fill bytes [4..hashSize) with 0xCC. After the call, if those
// sentinel bytes are unchanged, X-Ways didn't write -- treat as no-hash
// and skip dedup for this item. A real SHA-1/SHA-256 has effectively zero
// probability of being all-0xCC in those positions.
static std::string QueryItemHash(LONG itemID, DWORD hashSize) {
    if (!XWF_GetHashValue || hashSize == 0) return {};
    DWORD bufSize = (hashSize < 4 ? 4 : hashSize) + 16;
    std::vector<BYTE> buf(bufSize, 0);
    *reinterpret_cast<DWORD*>(buf.data()) = XWF_GETHASH_PRIMARY;
    constexpr BYTE kSentinel = 0xCC;
    for (DWORD i = 4; i < hashSize; ++i) buf[i] = kSentinel;

    if (!XWF_GetHashValue(itemID, buf.data())) return {};

    // No-write detection: sentinel bytes unchanged => X-Ways returned TRUE
    // without actually populating the hash (probably no hash computed for
    // this item). Caller treats this as "no hash" => no dedup.
    if (hashSize > 4) {
        bool sentinelIntact = true;
        for (DWORD i = 4; i < hashSize; ++i) {
            if (buf[i] != kSentinel) { sentinelIntact = false; break; }
        }
        if (sentinelIntact) return {};
    }
    return std::string(reinterpret_cast<char*>(buf.data()), hashSize);
}

// --- Module globals --------------------------------------------------------
static HMODULE g_hSelf    = nullptr;
static HWND    g_hMainWnd = nullptr;

// --- Verification enum -----------------------------------------------------
enum class VerifyMode { None, All, OnlyVerified };

// --- Findings-export mode (tri-state in the Output dialog group) ----------
//   None       no <evidence>-trufflehog.tsv emitted
//   Redacted   TSV emitted with the Redacted column (Raw is masked: first/
//              last 3 chars kept, middle bytes replaced with '*')
//   Full       TSV emitted with the full Raw / RawV2 / Redacted columns
//              (raw secret bytes preserved -- same exposure as the .jsonl
//              files in run\out\)
enum class FindingsOutputMode { None, Redacted, Full };

// How was the X-Tension launched? Display-only (the worker treats both the
// same way — it scans the items X-Ways already collected for us).
enum class InvocationMode { Run, Selection };

// --- Settings (round-trip via dialog LPARAM) -------------------------------
struct Settings {
    // Tool + paths
    std::wstring trufflehogExe;            // resolved absolute path
    std::wstring trufflehogVersion;        // detected (e.g. "trufflehog v3.95.3")
    std::wstring outputBase;               // base dir; runDir = outputBase\xways-trufflehog\run-...

    // Scope (filters that apply BEFORE we hand bytes to trufflehog)
    INT64        minSizeBytes      = 1;
    INT64        maxSizeMiB        = 256;      // 256 MiB ceiling
    bool         forceSkipBinaries = true;     // trufflehog --force-skip-binaries (X-Tension default ON)
    std::wstring filterEntropy     = L"3.0";   // trufflehog --filter-entropy=N (default 3.0; blank = off)
    std::wstring prefilterExtensions;          // CSV of extensions we skip before extracting (no dot, lowercase)

    // TruffleHog options
    VerifyMode   verifyMode    = VerifyMode::None;
    std::wstring includeDetectors;                                  // CSV
    std::wstring excludeDetectors = L"URI,JDBC";                    // CSV; forensic-noise defaults
    int          concurrency   = 0;        // 0 = let trufflehog decide
    std::wstring extraArgs;                // free-form pass-through (e.g.
                                            // --log-level=N, --archive-max-size=)

    // Custom-detector config -> trufflehog --config=<path>. Loads a YAML
    // pattern pack (name/regex/confidence triples) ON TOP of trufflehog's
    // built-in detectors. Empty = auto-resolve to the bundled pack at
    // <dll-dir>\tools\trufflehog\configs\secrets-patterns-db.yml if present.
    // Set to a single space to DISABLE auto-resolution and run with built-ins only.
    std::wstring customConfigPath;

    // Batch mode (perf -- one trufflehog invocation per N items)
    int          batchChunkSize  = 100;    // 0 = single batch; default 100 balances perf and cancel responsiveness

    // Hash dedup: skip scanning items whose primary hash matches an item we
    // already scanned in this run. Uses X-Ways' stored hash via
    // XWF_GetHashValue -- requires the analyst to have hashed the volume
    // snapshot first (Volume Snapshot Refinement -> "Compute hash" or similar).
    // Items without a stored hash bypass dedup transparently.
    bool         dedupByHash    = true;

    // Output
    bool         keepExtracted      = false;
    bool         addToReportTable   = true;
    bool         addComment         = true;
    int          tagThreshold       = 1;
    // Tri-state: drives the dialog's BS_AUTO3STATE checkbox.
    FindingsOutputMode findingsOutput = FindingsOutputMode::Full;
    // Split the XLSX into multiple files after this many findings rows. Hard-
    // capped at 1,000,000 at apply time (Excel's per-sheet limit is 1,048,576;
    // we leave headroom for the header row + future metadata). Default 500k
    // keeps individual files snappy on a high-FP run.
    int          findingsRowsPerSheet = 500000;

    // X-Tension diagnostic verbosity (toggles Log vs LogVerbose in the
    // X-Ways Messages window). For TruffleHog's own log level, pass
    // --log-level=N (or --log-level=-1 to silence) via Extra args.
    bool         verbose            = true;
};

// --- Run state passed from XT_Prepare into the dialog ----------------------
struct RunCtx {
    HANDLE             hVolume   = nullptr;
    HANDLE             hEvidence = nullptr;
    InvocationMode     invocationMode = InvocationMode::Run;
    std::vector<LONG>  items;          // filter-respecting list from XT_ProcessItem
    // X-Ways calls XT_ProcessItem for EVERY item in scope, including the
    // directory items themselves. Those are filtered out at scan time by
    // ShouldScan's XWF_ITEM_INFO_FLAG_DIRECTORY check, but if we showed
    // raw items.size() in the dialog the analyst would see a count much
    // higher than the X-Ways "Selected: N files" line and (rightly) wonder
    // what's going on. dirCount is populated once in ShowDialogAndRun and
    // displayed alongside the file count.
    size_t             dirCount = 0;
};

// --- Item accumulator (XT_ProcessItem -> XT_Finalize) ----------------------
//   Active for both Tools->Run X-Tension and right-click DBC: X-Ways calls
//   XT_ProcessItem for every item in the current view (filter-respected for
//   RUN; explicit selection for DBC). We just collect IDs here, then run the
//   dialog from XT_Finalize.
struct Collected {
    bool              ready = false;
    bool              aborted = false;  // user hit Stop/Esc during enumeration
    HANDLE            hVolume = nullptr;
    HANDLE            hEvidence = nullptr;
    InvocationMode    invocationMode = InvocationMode::Run;
    std::vector<LONG> items;
};
static Collected g_collected;

// --- Managed-mode (xways-xt-manager) state ---------------------------------
//   When this DLL is hosted by xways-xt-manager (instead of loaded directly
//   by X-Ways), the manager creates the embedded settings dialog with
//   lParam=0. The dialog proc + PopulateDialog need a Settings* / RunCtx* to
//   read/write; in managed mode they fall back to these module-local objects.
//
//   Lifecycle (mirrors the standalone XT_Prepare -> XT_ProcessItem ->
//   XT_Finalize flow, but driven by the manager's On* callbacks):
//     TrufflehogOnInit      -> resolve XWF_*, set g_managed_mode, LoadCfg into
//                              g_managed_settings so the embedded dialog shows
//                              cfg defaults at first display.
//     TrufflehogOnPrepare   -> reset g_managed_collected + stash volume/evidence
//                              handles; return true so the manager fans out
//                              per-item callbacks.
//     TrufflehogOnProcessItem(Ex) -> collect item IDs (mirror XT_ProcessItem).
//     TrufflehogHarvestSettings   -> read embedded dialog controls back into
//                              g_managed_settings (called by the manager
//                              immediately before OnFinalize-equivalent run).
//     TrufflehogOnFinalize  -> THE BATCH RUN POINT. Build a RunCtx from the
//                              collected items + run WorkerThread SYNCHRONOUSLY
//                              with hDlg=NULL (no embedded-dialog progress in
//                              logs stream to the X-Ways Messages window).
//
//   on_finalize (not on_prepare) runs the scan because trufflehog needs the
//   filter-respected item set, which only exists after every on_process_item
//   call completes. This differs from hindsight / ual-timeliner (which
//   enumerate their own items inside on_prepare and run there).
static bool      g_managed_mode = false;
static Settings  g_managed_settings;
static RunCtx    g_managed_runctx;     // fallback for SettingsDlgProc / PopulateDialog
static Collected g_managed_collected;  // item IDs gathered via OnProcessItem(Ex)

// =============================================================================
//  Helpers — logging, encoding, paths, files
// =============================================================================
static void Log(const std::wstring& msg) {
    std::wstring line = L"["; line += NAME; line += L"] "; line += msg;
    if (XWF_OutputMessage) XWF_OutputMessage(line.c_str(), 0);
}
static void LogVerbose(const std::wstring& msg) { if (g_verbose) Log(msg); }

static std::wstring FormatW(const wchar_t* fmt, ...) {
    wchar_t buf[2048];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    return buf;
}

template <typename T>
static T Resolve(HMODULE h, const char* name, int& missing) {
    T p = reinterpret_cast<T>(GetProcAddress(h, name));
    if (!p) ++missing;
    return p;
}

static int RetrieveFunctionPointers() {
    HMODULE h = GetModuleHandleW(nullptr);
    int missing = 0;
    XWF_OutputMessage      = Resolve<pfn_XWF_OutputMessage     >(h, "XWF_OutputMessage",      missing);
    XWF_GetItemName        = Resolve<pfn_XWF_GetItemName       >(h, "XWF_GetItemName",        missing);
    XWF_GetItemSize        = Resolve<pfn_XWF_GetItemSize       >(h, "XWF_GetItemSize",        missing);
    XWF_GetVolumeName      = Resolve<pfn_XWF_GetVolumeName     >(h, "XWF_GetVolumeName",      missing);
    XWF_AddToReportTable   = Resolve<pfn_XWF_AddToReportTable  >(h, "XWF_AddToReportTable",   missing);
    // XWF_Label is optional (21.7 SR-4+). Do NOT count it as missing --
    // pre-SR-4 hosts simply lack it and the fallback to XWF_AddToReportTable
    // keeps backward compatibility.
    XWF_Label              = reinterpret_cast<pfn_XWF_Label>(GetProcAddress(h, "XWF_Label"));
    XWF_AddComment         = Resolve<pfn_XWF_AddComment        >(h, "XWF_AddComment",         missing);
    XWF_GetEvObjProp       = Resolve<pfn_XWF_GetEvObjProp      >(h, "XWF_GetEvObjProp",       missing);
    XWF_Read               = Resolve<pfn_XWF_Read              >(h, "XWF_Read",               missing);
    XWF_OpenItem           = Resolve<pfn_XWF_OpenItem          >(h, "XWF_OpenItem",           missing);
    XWF_Close              = Resolve<pfn_XWF_Close             >(h, "XWF_Close",              missing);
    XWF_GetItemCount       = Resolve<pfn_XWF_GetItemCount      >(h, "XWF_GetItemCount",       missing);
    XWF_GetItemInformation = Resolve<pfn_XWF_GetItemInformation>(h, "XWF_GetItemInformation", missing);
    XWF_GetItemParent      = Resolve<pfn_XWF_GetItemParent     >(h, "XWF_GetItemParent",      missing);
    XWF_GetCaseProp        = Resolve<pfn_XWF_GetCaseProp       >(h, "XWF_GetCaseProp",        missing);
    XWF_GetVSProp          = Resolve<pfn_XWF_GetVSProp         >(h, "XWF_GetVSProp",          missing);
    XWF_GetHashValue       = Resolve<pfn_XWF_GetHashValue      >(h, "XWF_GetHashValue",       missing);
    // XWF_ShouldStop is optional (older builds may lack it).
    int dummy = 0;
    XWF_ShouldStop         = Resolve<pfn_XWF_ShouldStop        >(h, "XWF_ShouldStop",         dummy);
    return missing;
}

static std::wstring GetSelfDirectory() {
    wchar_t buf[MAX_PATH] = {0};
    DWORD n = GetModuleFileNameW(g_hSelf, buf, MAX_PATH);
    if (n == 0) return {};
    std::wstring p(buf, n);
    size_t slash = p.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? std::wstring() : p.substr(0, slash);
}

// Walk parent chain via XWF_GetItemParent + XWF_GetItemName to build the
// item's full path inside the volume snapshot (e.g. "Users\foo\.aws\creds").
// Returns empty if the resolvers are missing. Safety cap at 256 levels.
static std::wstring BuildItemFullPath(LONG itemID) {
    if (!XWF_GetItemName) return {};
    std::vector<std::wstring> parts;
    LONG cur = itemID;
    int safety = 0;
    while (cur >= 0 && safety < 256) {
        const wchar_t* nm = XWF_GetItemName(cur);
        if (nm && *nm) parts.emplace_back(nm);
        cur = XWF_GetItemParent ? XWF_GetItemParent(cur) : -1;
        ++safety;
    }
    std::wstring path;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        if (!path.empty()) path += L"\\";
        path += *it;
    }
    return path;
}

static std::wstring TrimW(const std::wstring& s) {
    size_t b = 0, e = s.size();
    while (b < e && iswspace(s[b])) ++b;
    while (e > b && iswspace(s[e - 1])) --e;
    return s.substr(b, e - b);
}

static std::wstring ToLowerW(const std::wstring& s) {
    std::wstring out = s; for (auto& c : out) c = (wchar_t)towlower(c); return out;
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], n, nullptr, nullptr);
    return out;
}

static bool FileExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static bool DirExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

static bool EnsureDirectoryExists(const std::wstring& path) {
    if (DirExists(path)) return true;
    if (CreateDirectoryW(path.c_str(), nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

static std::wstring SafeLeaf(const std::wstring& leaf) {
    std::wstring out; out.reserve(leaf.size());
    for (wchar_t c : leaf) {
        if (c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?' ||
            c == L'"'  || c == L'<' || c == L'>' || c == L'|') out.push_back(L'_');
        else out.push_back(c);
    }
    if (out.size() > 96) out.resize(96);
    return out;
}

static std::wstring CreateUniqueRunDir(const std::wstring& base) {
    SYSTEMTIME st; GetLocalTime(&st);
    for (int i = 0; i < 50; ++i) {
        wchar_t buf[64];
        if (i == 0) swprintf_s(buf, L"run-%04u%02u%02u-%02u%02u%02u",
                               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        else        swprintf_s(buf, L"run-%04u%02u%02u-%02u%02u%02u-%d",
                               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, i);
        std::wstring p = base + L"\\" + buf;
        if (CreateDirectoryW(p.c_str(), nullptr)) return p;
        if (GetLastError() != ERROR_ALREADY_EXISTS) return {};
    }
    return {};
}

// --- Output-base resolution ------------------------------------------------
//   XWF_GetCaseProp(NULL, 6, ...)   -> case directory   (docs/xways-getprop-reference.md)
//   XWF_GetEvObjProp(hEv, 12, ...)  -> evidence "Internally used directory"
//
//   Default output base is the case directory (so per-X-Tension artifacts
//   land with the case), falling back to evidence working dir, then %TEMP%.
//   The dialog/cfg always override this via Settings.outputBase.
static std::wstring GetCaseDirectory() {
    if (!XWF_GetCaseProp) return {};
    wchar_t buf[MAX_PATH] = {0};
    XWF_GetCaseProp(nullptr, /*nPropType=*/6, buf,
                    (LONG)(sizeof(buf) - sizeof(wchar_t)));
    return buf[0] ? std::wstring(buf) : std::wstring();
}

static std::wstring GetEvidenceWorkingDir(HANDLE hEvidence) {
    if (XWF_GetEvObjProp && hEvidence) {
        wchar_t buf[MAX_PATH] = {0};
        XWF_GetEvObjProp(hEvidence, /*nPropType=*/12, buf);
        if (buf[0]) return buf;
    }
    return {};
}

// Default output directory for a run -- ALREADY includes the X-Tension
// subfolder so the dialog edit field shows the actual destination (no
// hidden suffix). The worker uses this path directly; run dirs land at
// <returned>\run-YYYYMMDD-HHMMSS\.
//
// sourceLabel reports which step won (for the run log line).
static const wchar_t* kXtensionFolderName = L"xways-trufflehog";

static std::wstring ResolveDefaultOutputBase(HANDLE hEvidence,
                                             std::wstring& sourceLabel) {
    std::wstring caseDir = GetCaseDirectory();
    if (!caseDir.empty()) {
        sourceLabel = L"X-Ways case directory";
        return caseDir + L"\\" + kXtensionFolderName;
    }
    std::wstring evDir = GetEvidenceWorkingDir(hEvidence);
    if (!evDir.empty()) {
        sourceLabel = L"evidence working dir";
        return evDir + L"\\" + kXtensionFolderName;
    }
    wchar_t base[MAX_PATH] = {0};
    DWORD n = GetTempPathW(MAX_PATH, base);
    if (n > 0 && n <= MAX_PATH) {
        sourceLabel = L"%TEMP%";
        return std::wstring(base) + kXtensionFolderName;
    }
    sourceLabel = L"C:\\Temp\\ (last-resort)";
    return std::wstring(L"C:\\Temp\\") + kXtensionFolderName;
}

static bool ReadWholeFile(const std::wstring& path, std::string& out) {
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, path.c_str(), L"rb") != 0 || !fp) return false;
    char buf[8192];
    while (size_t n = fread(buf, 1, sizeof(buf), fp)) out.append(buf, n);
    fclose(fp);
    return true;
}

// =============================================================================
//  Cfg loader (sidecar xways-trufflehog.cfg next to the DLL)
// =============================================================================
static bool ParseBool(const std::wstring& v) {
    std::wstring lo = ToLowerW(TrimW(v));
    return lo == L"1" || lo == L"true" || lo == L"yes" || lo == L"on";
}
static INT64 ParseInt64(const std::wstring& v, INT64 fb) {
    if (v.empty()) return fb;
    try { return std::stoll(v); } catch (...) { return fb; }
}
static int ParseInt(const std::wstring& v, int fb) {
    if (v.empty()) return fb;
    try { return std::stoi(v); } catch (...) { return fb; }
}

// Serialize a Settings struct to cfg text. SINGLE SOURCE OF TRUTH for both
// the auto-created cfg AND for Run/Ctrl+Run saves -- guarantees the cfg
// values never drift from the Settings struct's compiled defaults.
//
// Custom comments the analyst types in the active-values section are NOT
// preserved across writes (that's the price of guaranteed in-sync values).
// The static REFERENCE block at the bottom is regenerated on every write.
static std::wstring SerializeSettings(const Settings& s) {
    auto bs = [](bool b) -> const wchar_t* { return b ? L"true" : L"false"; };
    // No VerifyMode serializer -- the cfg key `verify_mode=` is no longer
    // written as a live setting. See the commented-out reminder block
    // emitted below.
    auto fo = [](FindingsOutputMode m) -> const wchar_t* {
        return m == FindingsOutputMode::Full     ? L"full"
             : m == FindingsOutputMode::Redacted ? L"redacted"
             : L"none";
    };

    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t ts[64];
    swprintf_s(ts, L"%04u-%02u-%02u %02u:%02u:%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::wstring o;
    o += L"# xways-trufflehog.cfg\r\n";
    o += L"# Auto-managed by the X-Tension. Values reflect compiled defaults\r\n";
    o += L"# on first run, then the dialog state on each Run / Ctrl+Run.\r\n";
    o += L"# Last written: "; o += ts; o += L"\r\n";
    o += L"#\r\n";
    o += L"# Edits to values below take effect on the next dialog open.\r\n";
    o += L"# Custom comments in the active-settings section are NOT preserved\r\n";
    o += L"# across writes -- keep analyst notes in a separate file.\r\n\r\n";

    o += L"# ----- TruffleHog binary -----\r\n";
    o += L"trufflehog_exe="; o += s.trufflehogExe; o += L"\r\n";
    o += L"output_base=";    o += s.outputBase;    o += L"\r\n\r\n";

    o += L"# ----- Input filters -----\r\n";
    o += L"min_size_bytes="       + std::to_wstring(s.minSizeBytes) + L"\r\n";
    o += L"max_size_mib="         + std::to_wstring(s.maxSizeMiB)   + L"\r\n";
    o += L"force_skip_binaries="; o += bs(s.forceSkipBinaries);     o += L"\r\n";
    o += L"filter_entropy=";      o += s.filterEntropy;             o += L"\r\n";
    o += L"prefilter_extensions="; o += s.prefilterExtensions;      o += L"\r\n\r\n";

    o += L"# ----- Verification (key DEPRECATED) -----\r\n";
    o += L"# verify_mode= is ignored at run time. Verification is now opt-in\r\n";
    o += L"# SOLELY via extra_args=: add '--only-verified' to enable. The\r\n";
    o += L"# X-Tension always passes --no-verification unless extra_args says\r\n";
    o += L"# otherwise. A non-empty / non-'none' value in this key logs a\r\n";
    o += L"# warning on load and is otherwise ignored.\r\n";
    o += L"# verify_mode=none\r\n\r\n";

    o += L"# ----- Detectors -----\r\n";
    o += L"include_detectors="; o += s.includeDetectors; o += L"\r\n";
    o += L"exclude_detectors="; o += s.excludeDetectors; o += L"\r\n\r\n";

    o += L"# ----- TruffleHog tuning -----\r\n";
    o += L"concurrency=" + std::to_wstring(s.concurrency) + L"\r\n";
    o += L"# extra_args: pass-through (e.g. --log-level=-1 to silence trufflehog).\r\n";
    o += L"extra_args="; o += s.extraArgs;                  o += L"\r\n";
    o += L"# custom_config_path: trufflehog --config=<yml> (custom detector pack).\r\n";
    o += L"# Empty = auto-load <dll-dir>\\tools\\trufflehog\\configs\\secrets-patterns-db.yml\r\n";
    o += L"# if present (~784 extra detectors). Set to a single space ' ' to disable.\r\n";
    o += L"custom_config_path="; o += s.customConfigPath; o += L"\r\n\r\n";

    o += L"# ----- Batch + dedup (perf) -----\r\n";
    o += L"batch_chunk_size=" + std::to_wstring(s.batchChunkSize) + L"\r\n";
    o += L"dedup_by_hash=";   o += bs(s.dedupByHash);             o += L"\r\n\r\n";

    o += L"# ----- Output tagging -----\r\n";
    o += L"tag_threshold="        + std::to_wstring(s.tagThreshold) + L"\r\n";
    o += L"add_to_report_table="; o += bs(s.addToReportTable);      o += L"\r\n";
    o += L"add_comment=";         o += bs(s.addComment);            o += L"\r\n";
    o += L"keep_extracted_files="; o += bs(s.keepExtracted);        o += L"\r\n";
    o += L"# findings_output: none | redacted | full (default full)\r\n";
    o += L"findings_output=";     o += fo(s.findingsOutput);        o += L"\r\n";
    o += L"# findings_rows_per_sheet: split the XLSX after N rows (default 500000, hard cap 1000000).\r\n";
    o += L"findings_rows_per_sheet=" + std::to_wstring(s.findingsRowsPerSheet) + L"\r\n\r\n";

    o += L"# ----- X-Tension verbosity -----\r\n";
    o += L"xtension_verbose="; o += bs(s.verbose); o += L"\r\n\r\n";

    // Static reference block, always re-emitted on every write.
    o += L"# ============================================================\r\n";
    o += L"# REFERENCE (re-emitted on every write)\r\n";
    o += L"# Full doc + ~60 detector names: xways-trufflehog.cfg.example\r\n";
    o += L"# (deployed alongside the DLL by build.bat).\r\n";
    o += L"#\r\n";
    o += L"#   verify_mode:      none | all | only_verified\r\n";
    o += L"#   batch_chunk_size: 0 = single batch;\r\n";
    o += L"#                     cfg [10..20000]; dialog [10..5000]\r\n";
    o += L"#\r\n";
    o += L"# Common include/exclude detector names (case-sensitive):\r\n";
    o += L"#   AWS  GCP  AzureStorage  DigitalOceanV2  Heroku\r\n";
    o += L"#   Github  Gitlab  BitbucketAppPwd\r\n";
    o += L"#   Slack  Twilio  Mailchimp  SendGrid  Stripe  Postman\r\n";
    o += L"#   MongoDB  Postgres  Mysql  JDBC  Redis  Snowflake\r\n";
    o += L"#   PrivateKey  JWT  NpmToken  Box  Dropbox\r\n";
    o += L"#\r\n";
    o += L"# Useful extra_args:\r\n";
    o += L"#   --archive-max-depth=2 --archive-max-size=50MB\r\n";
    o += L"#   --detector-timeout=30s --max-decode-depth=5\r\n";
    o += L"#   --filter-unverified\r\n";
    o += L"#   --results=unverified,filtered_unverified\r\n";
    o += L"#   --print-avg-detector-time\r\n";
    o += L"# ============================================================\r\n";
    return o;
}

// Atomic-ish cfg write: back up any existing cfg to <path>.bak, then
// overwrite. UTF-8 BOM + CRLF body so Notepad opens it cleanly on Windows.
static bool SaveSettingsToCfg(const std::wstring& path, const Settings& s) {
    if (FileExists(path)) {
        std::wstring bak = path + L".bak";
        DeleteFileW(bak.c_str());
        // MoveFileW preserves the original file's timestamps + is faster
        // on the same volume than CopyFileW.
        MoveFileW(path.c_str(), bak.c_str());
    }
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, path.c_str(), L"wb") != 0 || !fp) return false;
    const unsigned char bom[] = {0xEF, 0xBB, 0xBF};
    fwrite(bom, 1, 3, fp);
    std::string utf8 = WideToUtf8(SerializeSettings(s));
    fwrite(utf8.data(), 1, utf8.size(), fp);
    fclose(fp);
    return true;
}

// Ensure the cfg file exists at the resolved path. If absent, write a fresh
// cfg from the default Settings via the same serializer used by Run/Save --
// guarantees the auto-created cfg can't drift from the X-Tension's compiled
// defaults.
static bool EnsureCfgExists(const std::wstring& cfgPath) {
    if (FileExists(cfgPath)) return true;
    Settings defaults;
    if (SaveSettingsToCfg(cfgPath, defaults)) {
        Log(L"created default cfg: " + cfgPath);
        return true;
    }
    Log(L"failed to create default cfg at: " + cfgPath);
    return false;
}

static void LoadCfg(const std::wstring& path, Settings& s) {
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, path.c_str(), L"rb") != 0 || !fp) {
        LogVerbose(L"cfg not found (using defaults): " + path);
        return;
    }
    Log(L"loading cfg: " + path);
    char buf[4096]; std::string acc;
    while (size_t n = fread(buf, 1, sizeof(buf), fp)) acc.append(buf, n);
    fclose(fp);
    if (acc.size() >= 3 &&
        (unsigned char)acc[0] == 0xEF && (unsigned char)acc[1] == 0xBB && (unsigned char)acc[2] == 0xBF) acc.erase(0, 3);
    std::wstring all = Utf8ToWide(acc);
    size_t lineStart = 0;
    for (size_t i = 0; i <= all.size(); ++i) {
        if (i != all.size() && all[i] != L'\n' && all[i] != L'\r') continue;
        std::wstring line = TrimW(all.substr(lineStart, i - lineStart));
        lineStart = i + 1;
        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring key = TrimW(line.substr(0, eq));
        std::wstring val = TrimW(line.substr(eq + 1));
        if      (key == L"trufflehog_exe")       s.trufflehogExe       = val;
        else if (key == L"output_base")          s.outputBase          = val;
        else if (key == L"include_detectors")    s.includeDetectors    = val;
        else if (key == L"exclude_detectors")    s.excludeDetectors    = val;
        else if (key == L"extra_args")           s.extraArgs           = val;
        else if (key == L"log_level") {
            // Legacy cfg key. Forward into extra_args
            // so the analyst's previous value still takes effect without
            // them having to retype it. Idempotent: only fold in once.
            if (!val.empty() && val.find_first_not_of(L" \t") != std::wstring::npos) {
                std::wstring flag = L"--log-level=" + TrimW(val);
                if (s.extraArgs.find(L"--log-level") == std::wstring::npos) {
                    if (!s.extraArgs.empty()) s.extraArgs += L" ";
                    s.extraArgs += flag;
                }
            }
        }
        else if (key == L"concurrency")          s.concurrency         = ParseInt(val, s.concurrency);
        else if (key == L"min_size_bytes")       s.minSizeBytes        = ParseInt64(val, s.minSizeBytes);
        else if (key == L"max_size_mib")         s.maxSizeMiB          = ParseInt64(val, s.maxSizeMiB);
        else if (key == L"force_skip_binaries")  s.forceSkipBinaries   = ParseBool(val);
        else if (key == L"filter_entropy")       s.filterEntropy       = val;
        else if (key == L"prefilter_extensions") s.prefilterExtensions = val;
        else if (key == L"batch_chunk_size") {
            int v = ParseInt(val, s.batchChunkSize);
            // 0 = "single batch" sentinel kept. Otherwise clamp to [10, 20000].
            // Dialog separately clamps to [10, 5000]; cfg can push higher for
            // analysts who want to experiment beyond the conservative UI cap.
            if (v != 0) {
                if (v < 10)    v = 10;
                if (v > 20000) v = 20000;
            }
            s.batchChunkSize = v;
        }
        else if (key == L"dedup_by_hash")        s.dedupByHash         = ParseBool(val);
        else if (key == L"tag_threshold")        s.tagThreshold        = ParseInt(val, s.tagThreshold);
        else if (key == L"keep_extracted_files") s.keepExtracted       = ParseBool(val);
        else if (key == L"add_to_report_table")  s.addToReportTable    = ParseBool(val);
        else if (key == L"add_comment")          s.addComment          = ParseBool(val);
        else if (key == L"xtension_verbose"
              || key == L"verbose")              s.verbose             = ParseBool(val);
        else if (key == L"verify_mode") {
            // Legacy key. The value is IGNORED -- a stale `verify_mode=all`
            // in a long-lived cfg used to silently re-enable live verification
            // with no UI cue, so verification is now opt-in SOLELY via
            // extra_args. Warn on non-none / non-empty so the analyst can
            // see why their old setting no longer takes effect.
            std::wstring lo = ToLowerW(val);
            if (!lo.empty() && lo != L"none" && lo != L"no_verification") {
                Log(L"cfg: ignoring legacy verify_mode=" + val +
                    L" (key deprecated; add --only-verified to extra_args "
                    L"to opt into live verification)");
            }
            s.verifyMode = VerifyMode::None;  // canonical -- no other state is reachable
        }
        else if (key == L"custom_config_path") s.customConfigPath = val;
        else if (key == L"findings_output") {
            std::wstring lo = ToLowerW(val);
            if      (lo == L"none" || lo == L"off" || lo == L"0")        s.findingsOutput = FindingsOutputMode::None;
            else if (lo == L"redacted" || lo == L"half" || lo == L"mid") s.findingsOutput = FindingsOutputMode::Redacted;
            else                                                          s.findingsOutput = FindingsOutputMode::Full;
        }
        else if (key == L"findings_rows_per_sheet") {
            int v = ParseInt(val, s.findingsRowsPerSheet);
            if (v < 1)        v = 1;
            if (v > 1000000)  v = 1000000;
            s.findingsRowsPerSheet = v;
        }
    }
}

// =============================================================================
//  Subprocess invocation
// =============================================================================
//   RunCommand: redirect stdout/stderr via cmd.exe, wait for exit.
//   RunCaptureStdout: read child stdout into a string (for --version probe).
static bool RunCommand(const std::wstring& cmdline, const std::wstring& workingDir,
                       DWORD& exitCodeOut) {
    std::vector<wchar_t> mut(cmdline.begin(), cmdline.end());
    mut.push_back(L'\0');
    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(nullptr, mut.data(), nullptr, nullptr, FALSE,
                             CREATE_NO_WINDOW, nullptr,
                             workingDir.empty() ? nullptr : workingDir.c_str(),
                             &si, &pi);
    if (!ok) { exitCodeOut = (DWORD)-1; return false; }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCodeOut);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

static DWORD RunCaptureStdout(const std::wstring& cmd, std::string& out, DWORD timeoutMs = 5000) {
    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return (DWORD)-1;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si = {}; si.cb = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> cmdline(cmd.begin(), cmd.end()); cmdline.push_back(L'\0');
    BOOL ok = CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);
    if (!ok) { CloseHandle(hRead); return (DWORD)-1; }
    out.clear();
    char buf[1024];
    DWORD readBytes;
    DWORD deadline = GetTickCount() + timeoutMs;
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(hRead, nullptr, 0, nullptr, &avail, nullptr)) break;
        if (avail == 0) {
            DWORD wait = WaitForSingleObject(pi.hProcess, 50);
            if (wait == WAIT_OBJECT_0) break;
            if ((LONG)(deadline - GetTickCount()) <= 0) {
                TerminateProcess(pi.hProcess, 1);
                break;
            }
            continue;
        }
        if (!ReadFile(hRead, buf, sizeof(buf), &readBytes, nullptr) || readBytes == 0) break;
        out.append(buf, readBytes);
        if (out.size() > 65536) break;
    }
    // Drain any remaining stdout after the process exits.
    while (ReadFile(hRead, buf, sizeof(buf), &readBytes, nullptr) && readBytes > 0) {
        out.append(buf, readBytes);
        if (out.size() > 65536) break;
    }
    WaitForSingleObject(pi.hProcess, 1000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode;
}

// =============================================================================
//  Item extraction (XWF_Read on opened hItem -> CreateFile)
// =============================================================================
static bool ExtractItemToFile(HANDLE hItem, INT64 size, const std::wstring& destPath) {
    if (!XWF_Read || size < 0) return false;
    HANDLE hFile = CreateFileW(destPath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    constexpr DWORD kChunk = 64 * 1024;
    std::vector<BYTE> buf(kChunk);
    INT64 offset = 0;
    bool ok = true;
    while (offset < size) {
        DWORD want = (DWORD)std::min<INT64>(kChunk, size - offset);
        DWORD got = XWF_Read(hItem, offset, buf.data(), want);
        if (got == 0) { ok = false; break; }
        DWORD written = 0;
        if (!WriteFile(hFile, buf.data(), got, &written, nullptr) || written != got) {
            ok = false; break;
        }
        offset += got;
    }
    CloseHandle(hFile);
    return ok;
}

// =============================================================================
//  JSONL scanner (trufflehog --json output)
// =============================================================================
struct Finding {
    std::wstring detector;
    bool         verified = false;
    INT64        line     = -1;
    std::wstring raw;          // RAW secret bytes -- present only when JSONL provides
    std::wstring rawV2;        // alternate raw form (e.g. structured key/value)
    std::wstring redacted;     // safe-to-display form (TruffleHog's "Redacted" field)
    std::wstring decoder;      // PLAIN / BASE64 / ESCAPED_UNICODE / ...
    std::wstring description;  // detector description (one-line vendor blurb)
};

struct Findings {
    std::vector<Finding>    rows;
    std::set<std::wstring>  detectors;  // unique set, built alongside rows
    size_t total()         const { return rows.size(); }
    size_t verifiedCount() const {
        size_t n = 0; for (const auto& r : rows) if (r.verified) ++n; return n;
    }
    INT64  firstLine() const {
        for (const auto& r : rows) if (r.line > 0) return r.line;
        return -1;
    }
};

// One row in the consolidated findings.tsv at end of run.
struct FindingRow {
    LONG         itemID = -1;
    std::wstring name;          // leaf
    std::wstring path;          // full path inside snapshot
    std::wstring detector;
    bool         verified = false;
    INT64        line = -1;
    std::wstring raw;           // RAW secret bytes (Full mode only -- masked in Redacted mode)
    std::wstring rawV2;         // RawV2 (Full mode only)
    std::wstring redacted;      // TruffleHog's safe summary (both modes)
    std::wstring decoder;       // PLAIN / BASE64 / ESCAPED_UNICODE / ...
    std::wstring description;   // detector description
};

static std::string ExtractJsonString(const std::string& line, const char* key) {
    std::string needle = "\""; needle += key; needle += "\"";
    size_t pos = line.find(needle);
    if (pos == std::string::npos) return {};
    size_t p = pos + needle.size();
    while (p < line.size() && isspace((unsigned char)line[p])) ++p;
    if (p >= line.size() || line[p] != ':') return {};
    ++p;
    while (p < line.size() && isspace((unsigned char)line[p])) ++p;
    if (p >= line.size() || line[p] != '"') return {};
    ++p;
    std::string out;
    while (p < line.size()) {
        if (line[p] == '\\' && p + 1 < line.size()) { out.push_back(line[p+1]); p += 2; continue; }
        if (line[p] == '"') return out;
        out.push_back(line[p]);
        ++p;
    }
    return out;
}

static bool ExtractJsonBoolTrue(const std::string& line, const char* key) {
    std::string needle = "\""; needle += key; needle += "\"";
    size_t pos = line.find(needle);
    if (pos == std::string::npos) return false;
    size_t p = pos + needle.size();
    while (p < line.size() && isspace((unsigned char)line[p])) ++p;
    if (p >= line.size() || line[p] != ':') return false;
    ++p;
    while (p < line.size() && isspace((unsigned char)line[p])) ++p;
    return (p + 4 <= line.size() && line.compare(p, 4, "true") == 0);
}

// TruffleHog assigns every custom-detector finding the umbrella
// DetectorName "CustomRegex" -- the actual per-detector name from the
// `--config` YAML lives in ExtraData.name (e.g. ExtraData={"name":"Ipstack"}).
// Pull it out so our per-detector report tables stay granular for custom
// hits too instead of bucketing all 784 into one "CustomRegex" table.
//
// Walks the JSON object after `"ExtraData":` brace-by-brace so it doesn't
// trip on `{` or `}` inside string values.
static std::string ExtractExtraDataName(const std::string& line) {
    const std::string kEdKey = "\"ExtraData\":";
    size_t ed = line.find(kEdKey);
    if (ed == std::string::npos) return {};
    size_t p = ed + kEdKey.size();
    while (p < line.size() && line[p] != '{') {
        if (line[p] == 'n') return {};  // ExtraData: null
        ++p;
    }
    if (p >= line.size()) return {};
    int depth = 1;
    size_t end = p + 1;
    while (end < line.size() && depth > 0) {
        char c = line[end];
        if (c == '"') {
            ++end;
            while (end < line.size() && line[end] != '"') {
                if (line[end] == '\\' && end + 1 < line.size()) end += 2;
                else ++end;
            }
            if (end < line.size()) ++end;
            continue;
        }
        if (c == '{') ++depth;
        else if (c == '}') { --depth; if (depth == 0) { ++end; break; } }
        ++end;
    }
    std::string ed_obj(line, p, end - p);
    return ExtractJsonString(ed_obj, "name");
}

// Final detector label: TruffleHog's DetectorName, OR for custom-pattern
// hits (DetectorName == "CustomRegex"), the more specific ExtraData.name
// prefixed with "custom:" so analysts can distinguish built-in vs custom.
static std::string ResolveDetectorLabel(const std::string& line, const std::string& detectorName) {
    if (detectorName != "CustomRegex") return detectorName;
    std::string custom = ExtractExtraDataName(line);
    if (custom.empty()) return detectorName;
    return "custom:" + custom;
}

// Extract numeric "line": N from a line. Returns -1 if absent.
static INT64 ExtractJsonNumber(const std::string& line, const char* key) {
    std::string needle = "\""; needle += key; needle += "\"";
    size_t pos = line.find(needle);
    if (pos == std::string::npos) return -1;
    size_t p = pos + needle.size();
    while (p < line.size() && isspace((unsigned char)line[p])) ++p;
    if (p >= line.size() || line[p] != ':') return -1;
    ++p;
    while (p < line.size() && isspace((unsigned char)line[p])) ++p;
    INT64 v = 0; bool any = false;
    while (p < line.size() && line[p] >= '0' && line[p] <= '9') {
        v = v * 10 + (line[p] - '0'); ++p; any = true;
    }
    return any ? v : -1;
}

static void ScanJsonl(const std::string& jsonl, Findings& out) {
    size_t lineStart = 0;
    for (size_t i = 0; i <= jsonl.size(); ++i) {
        if (i != jsonl.size() && jsonl[i] != '\n') continue;
        if (i > lineStart) {
            size_t end = i;
            while (end > lineStart && (jsonl[end-1] == '\r' || isspace((unsigned char)jsonl[end-1]))) --end;
            if (end > lineStart && jsonl[lineStart] == '{') {
                std::string ln(jsonl, lineStart, end - lineStart);
                std::string det = ExtractJsonString(ln, "DetectorName");
                if (!det.empty()) {
                    Finding f;
                    f.detector    = Utf8ToWide(ResolveDetectorLabel(ln, det));
                    f.verified    = ExtractJsonBoolTrue(ln, "Verified");
                    f.line        = ExtractJsonNumber(ln, "line");
                    f.raw         = Utf8ToWide(ExtractJsonString(ln, "Raw"));
                    f.rawV2       = Utf8ToWide(ExtractJsonString(ln, "RawV2"));
                    f.redacted    = Utf8ToWide(ExtractJsonString(ln, "Redacted"));
                    f.decoder     = Utf8ToWide(ExtractJsonString(ln, "DecoderName"));
                    f.description = Utf8ToWide(ExtractJsonString(ln, "DetectorDescription"));
                    // If Redacted is empty (older trufflehog or some detectors)
                    // fall back to Raw so downstream code always has something.
                    if (f.redacted.empty()) f.redacted = f.raw;
                    out.detectors.insert(f.detector);
                    out.rows.push_back(std::move(f));
                }
            }
        }
        lineStart = i + 1;
    }
}

// =============================================================================
//  TruffleHog detection (--version)
// =============================================================================
//   Run once per dialog open. Returns the first non-empty line of `<exe>
//   --version` output (e.g. "trufflehog 3.95.3") or "" if the probe failed,
//   the file isn't an exe, or the output looked like an argparse fallback
//   ("usage:", "error:", "unrecognized arguments") rather than a real
//   version banner. The filter matches the spec in
//   docs/xtension-invocation.md and the canonical helper-identity pattern
//   in CLAUDE.md: an exe that doesn't recognize --version often prints
//   one of those banners, and we must NOT treat that as a passing banner.
static std::wstring DetectTrufflehogVersion(const std::wstring& exe) {
    if (exe.empty() || !FileExists(exe)) return {};
    std::wstring cmd = L"\""; cmd += exe; cmd += L"\" --version";
    std::string out;
    DWORD ec = RunCaptureStdout(cmd, out, 5000);
    (void)ec;  // trufflehog --version exit code varies; trust output.
    // Output looks like:  "trufflehog 3.95.3\n"  on stderr OR stdout
    // depending on release. RunCaptureStdout piped both into `out`.
    std::wstring w = TrimW(Utf8ToWide(out));
    size_t nl = w.find_first_of(L"\r\n");
    if (nl != std::wstring::npos) w.resize(nl);
    // Discard argparse fallback banners so a renamed-but-not-trufflehog
    // exe (or a tool that doesn't recognize --version) can't slip past
    // the banner identity check downstream.
    std::wstring lowered = ToLowerW(w);
    if (lowered.rfind(L"usage:", 0) == 0)                 return {};
    if (lowered.find(L"error:") != std::wstring::npos)    return {};
    if (lowered.find(L"unrecognized arguments") != std::wstring::npos) return {};
    return w;
}

// =============================================================================
//  Helper-exe identity verification (canonical pattern -- CLAUDE.md spec)
// =============================================================================
// PE VERSIONINFO substring check on InternalName / OriginalFilename /
// ProductName / FileDescription. Returns true on first hit. Works for native
// Win32 binaries and PyInstaller exes that ship a populated VERSIONINFO.
//
// Note: trufflesecurity/trufflehog is built with goreleaser + plain `go
// build`, which does NOT embed Windows VERSIONINFO. So this check ALWAYS
// returns false for real trufflehog binaries today; the banner check in
// VerifyHelperIdentity is what carries the load. The PE check is still
// included for (a) future-proofing if upstream starts shipping a .syso, and
// (b) consistency with the canonical pattern documented in CLAUDE.md.
static const wchar_t* kHelperIdentityNeedle = L"trufflehog";

static bool PeIdentityContains(const std::wstring& exePath,
                               const wchar_t* needleLower) {
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(exePath.c_str(), &handle);
    if (size == 0) return false;
    std::vector<BYTE> buf(size);
    if (!GetFileVersionInfoW(exePath.c_str(), handle, size, buf.data())) return false;

    struct LCP { WORD wLanguage; WORD wCodePage; };
    LCP* lcp = nullptr;
    UINT lcpLen = 0;
    if (!VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation",
                        (LPVOID*)&lcp, &lcpLen) || !lcp || lcpLen < sizeof(LCP))
        return false;

    // Translation block can hold multiple language/codepage pairs. Walk them
    // all so a binary that only populates a non-English VERSIONINFO is still
    // recognised. (Hindsight's PyInstaller pack does this.)
    const size_t nLangs = lcpLen / sizeof(LCP);
    const wchar_t* fields[] = {
        L"InternalName", L"OriginalFilename", L"ProductName", L"FileDescription"
    };
    for (size_t li = 0; li < nLangs; ++li) {
        for (const wchar_t* f : fields) {
            wchar_t sub[100];
            swprintf_s(sub, L"\\StringFileInfo\\%04x%04x\\%s",
                       lcp[li].wLanguage, lcp[li].wCodePage, f);
            wchar_t* val = nullptr;
            UINT vlen = 0;
            if (VerQueryValueW(buf.data(), sub, (LPVOID*)&val, &vlen) && val) {
                std::wstring s = ToLowerW(val);
                if (s.find(needleLower) != std::wstring::npos) return true;
            }
        }
    }
    return false;
}

// VerifyHelperIdentity composes the PE check and the --version banner check.
// Returns true if EITHER passes (per the CLAUDE.md spec). Populates outDetail
// with a human-readable explanation of which check(s) passed -- logged on
// rejection and shown in the dialog readout on success.
static bool VerifyHelperIdentity(const std::wstring& exePath,
                                 const wchar_t* needle,
                                 std::wstring& outVersionLine,
                                 std::wstring& outDetail) {
    std::wstring needleLower = ToLowerW(needle);

    bool pe   = PeIdentityContains(exePath, needleLower.c_str());
    bool flag = false;
    outVersionLine = DetectTrufflehogVersion(exePath);
    if (!outVersionLine.empty()) {
        std::wstring lower = ToLowerW(outVersionLine);
        if (lower.find(needleLower) != std::wstring::npos) flag = true;
    }

    if (pe && flag)  outDetail = L"PE VERSIONINFO + --version banner match";
    else if (pe)     outDetail = L"PE VERSIONINFO match";
    else if (flag)   outDetail = L"--version banner match";
    else             outDetail = L"no \"" + std::wstring(needle) +
                                  L"\" marker in PE VERSIONINFO or --version output";
    return pe || flag;
}

// Bounded breadth-first scan for a partnered binary anywhere under `root`.
// Returns the shallowest match (so a copy directly next to the DLL beats one
// nested under tools\trufflehog\). Bounded by maxDepth and a directory-visit
// budget to keep an accidental scan over a huge case-output subtree cheap.
// Skips well-known nuisance dirs (.git, .vs, node_modules, __pycache__) and
// hidden directories.
static std::wstring FindSiblingFile(const std::wstring& root,
                                    const wchar_t* targetName,
                                    int maxDepth = 4,
                                    int maxDirsVisited = 256) {
    if (root.empty() || !targetName || !*targetName) return {};
    struct Entry { std::wstring dir; int depth; };
    std::vector<Entry> queue;
    queue.push_back({ root, 0 });

    int visited = 0;
    for (size_t i = 0; i < queue.size() && visited < maxDirsVisited; ++i) {
        const Entry e = queue[i];
        ++visited;

        // Check for the file directly in this directory (BFS = shallowest wins).
        std::wstring candidate = e.dir + L"\\" + targetName;
        if (FileExists(candidate)) return candidate;
        if (e.depth >= maxDepth) continue;

        WIN32_FIND_DATAW fd = {};
        std::wstring pattern = e.dir + L"\\*";
        HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (fd.cFileName[0] == L'.') continue;  // skip . / .. / hidden dotdirs
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) continue;
            const wchar_t* nm = fd.cFileName;
            if (!_wcsicmp(nm, L".git") || !_wcsicmp(nm, L".vs") ||
                !_wcsicmp(nm, L"node_modules") || !_wcsicmp(nm, L"__pycache__")) continue;
            queue.push_back({ e.dir + L"\\" + nm, e.depth + 1 });
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return {};
}

// Locate trufflehog.exe alongside the DLL. Tries the conventional bundled
// paths first (cheap stat calls), then falls back to a bounded recursive
// search so analyst layouts like tools\trufflehog.exe (no nested folder)
// also auto-resolve. The dialog Browse button always lets the analyst
// override; this just removes the friction when the binary IS deployed
// somewhere sensible under the X-Tension folder.
static std::wstring ResolveDefaultTrufflehog() {
    std::wstring dllDir = GetSelfDirectory();
    if (dllDir.empty()) return {};
    for (const wchar_t* sub : {
            L"\\tools\\trufflehog\\trufflehog.exe",
            L"\\tools\\trufflehog.exe",
            L"\\trufflehog.exe",
         }) {
        std::wstring guess = dllDir + sub;
        if (FileExists(guess)) return guess;
    }
    return FindSiblingFile(dllDir, L"trufflehog.exe");
}

// Async version + identity probe. DetectTrufflehogVersion spawns a subprocess
// and waits up to 5s; PeIdentityContains reads PE VERSIONINFO synchronously
// (microseconds). Doing both on the main UI thread before DialogBoxParamW
// stacks onto the X-Ways DBC per-item enumeration freeze and pushes the
// total "Not Responding" window long enough that Windows or the analyst may
// kill X-Ways. The dialog opens with "Version: (detecting...)" and updates
// via WM_APP_VERSION when the probe completes.
//
// Payload structure: the worker thread runs the FULL identity check (both
// PE and banner) and posts a VersionProbeResult struct. The dialog handler
// just renders -- no heavy work on the UI thread.
struct VersionProbeArgs {
    HWND         hDlg;
    std::wstring exe;
    unsigned     token;        // see g_probeToken
};

struct VersionProbeResult {
    std::wstring exe;          // the path that was probed (for the rejection label)
    std::wstring versionLine;  // first non-empty line of --version output (may be empty)
    std::wstring detail;       // human-readable explanation: which check(s) passed
    bool         valid = false; // PE check OR banner check matched the needle
    bool         fileExists = false; // FileExists(exe) at probe time
    unsigned     token = 0;    // matches the g_probeToken value at probe-start
};

// Monotonically-increasing probe sequence. Incremented by StartAsyncVersionProbe
// on every new probe; WM_APP_VERSION discards results whose token doesn't
// match the current value, which closes the rapid-Browse race where an OLD
// (slow) probe's "valid" result could otherwise arrive AFTER a NEW (fast)
// probe's rejection and re-enable Run for the WRONG exe -- the exact
// footgun the identity gate is supposed to prevent.
static std::atomic<unsigned> g_probeToken{0};

static unsigned __stdcall VersionProbeThread(void* arg) {
    auto* a = static_cast<VersionProbeArgs*>(arg);
    auto* res = new VersionProbeResult{};
    res->exe        = a->exe;
    res->token      = a->token;
    res->fileExists = FileExists(a->exe);
    if (res->fileExists) {
        res->valid = VerifyHelperIdentity(a->exe, kHelperIdentityNeedle,
                                          res->versionLine, res->detail);
    } else {
        res->valid  = false;
        res->detail = L"file not found at picked path";
    }
    // PostMessage fails silently if the dialog was already closed -- clean up
    // the heap allocation to avoid leaking when the user clicks Cancel during
    // the probe. (WM_DESTROY also drains any in-flight WM_APP_VERSION posts
    // for the same reason -- belt and braces.)
    if (!PostMessageW(a->hDlg, WM_APP_VERSION, 0, (LPARAM)res)) {
        delete res;
    }
    delete a;
    return 0;
}

static void StartAsyncVersionProbe(HWND hDlg, const std::wstring& exe) {
    if (exe.empty() || !hDlg) return;
    unsigned token = ++g_probeToken;   // stamp this probe; older posts get discarded
    auto* a = new VersionProbeArgs{hDlg, exe, token};
    HANDLE h = (HANDLE)_beginthreadex(nullptr, 0, VersionProbeThread, a, 0, nullptr);
    if (!h) { delete a; return; }
    CloseHandle(h);  // detached -- result delivered via PostMessage
}

// Resolve the trufflehog --config=<path> value for this run.
//   - empty cfg setting -> no custom config; trufflehog runs with its
//     built-in detectors only.
//   - non-empty cfg setting -> used verbatim. A whitespace-only string is
//     treated as empty so analysts can explicitly disable any inherited
//     path by setting `custom_config_path= ` in the cfg.
static std::wstring ResolveCustomConfigPath(const Settings& s) {
    if (s.customConfigPath.empty()) return {};
    std::wstring trimmed = TrimW(s.customConfigPath);
    if (trimmed.empty()) return {};
    return s.customConfigPath;
}

// =============================================================================
//  Browse helpers
// =============================================================================
static std::wstring BrowseForFile(HWND parent, const std::wstring& current) {
    wchar_t buf[MAX_PATH] = {0};
    if (!current.empty() && current.size() < MAX_PATH) wcscpy_s(buf, current.c_str());

    // Anchor the picker. Without lpstrInitialDir, Windows falls back to the
    // process-wide most-recent-used common-dialog folder -- so if the analyst
    // last picked a file via a *different* X-Tension's Browse dialog (e.g.
    // hindsight.exe under xtensions\xways-hindsight\), our Browse opens there
    // instead of next to our own DLL. Anchor to: current path's dir if set,
    // else our X-Tension's own DLL folder. OFN_NOCHANGEDIR keeps the dialog
    // from mutating the process CWD as a side effect.
    std::wstring initDir;
    if (!current.empty()) {
        size_t slash = current.find_last_of(L"\\/");
        if (slash != std::wstring::npos) initDir = current.substr(0, slash);
    }
    if (initDir.empty()) initDir = GetSelfDirectory();

    OPENFILENAMEW ofn = {};
    ofn.lStructSize     = sizeof(ofn);
    ofn.hwndOwner       = parent;
    ofn.lpstrFilter     = L"Executable (*.exe)\0*.exe\0All files (*.*)\0*.*\0";
    ofn.lpstrFile       = buf;
    ofn.nMaxFile        = MAX_PATH;
    ofn.lpstrTitle      = L"Select trufflehog.exe";
    ofn.lpstrInitialDir = initDir.empty() ? nullptr : initDir.c_str();
    ofn.Flags           = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY |
                          OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn)) return current;
    return buf;
}

// Modern folder picker using IFileOpenDialog (Vista+). Picks one folder.
// Has an always-visible "New folder" toolbar button (better UX than the
// legacy SHBrowseForFolderW dialog, which buries the equivalent option).
// Returns the picked path, or `current` on Cancel.
//
// `title` lets callers distinguish e.g. "Select output directory" from
// "Select destination for the cfg copy".
static std::wstring BrowseForFolder(HWND parent, const std::wstring& current,
                                    const wchar_t* title = L"Select folder") {
    // COM init scoped to this call. CoInitializeEx may return S_FALSE if
    // already initialized in this thread (also success).
    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    std::wstring picked = current;

    IFileOpenDialog* dlg = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&dlg));
    if (SUCCEEDED(hr) && dlg) {
        DWORD opts = 0;
        dlg->GetOptions(&opts);
        // FOS_PICKFOLDERS: folder-only picker.
        // FOS_FORCEFILESYSTEM: only return real filesystem paths.
        // FOS_PATHMUSTEXIST: starting folder must exist (defensive).
        dlg->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
        dlg->SetTitle(title);

        // Pre-seed default folder if current is a valid existing dir.
        if (!current.empty()) {
            IShellItem* psi = nullptr;
            if (SUCCEEDED(SHCreateItemFromParsingName(current.c_str(), nullptr, IID_PPV_ARGS(&psi))) && psi) {
                dlg->SetDefaultFolder(psi);
                psi->Release();
            }
        }

        if (SUCCEEDED(dlg->Show(parent))) {
            IShellItem* result = nullptr;
            if (SUCCEEDED(dlg->GetResult(&result)) && result) {
                PWSTR path = nullptr;
                if (SUCCEEDED(result->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path) {
                    picked = path;
                    CoTaskMemFree(path);
                }
                result->Release();
            }
        }
        dlg->Release();
    }

    if (SUCCEEDED(hrInit)) CoUninitialize();
    return picked;
}

// =============================================================================
//  Worker-thread state — owned by the dialog while a scan runs
// =============================================================================
struct WorkerCtx {
    Settings*       s   = nullptr;
    RunCtx*         ctx = nullptr;
    HWND            hDlg = nullptr;

    // Resolved at run start.
    std::wstring    runDir;
    std::wstring    inDir;
    std::wstring    outDir;

    // Live progress.
    std::atomic<bool> cancelRequested {false};

    // Final stats (written by worker, read by dialog on DONE).
    size_t          itemsSeen      = 0;
    size_t          itemsScanned   = 0;
    size_t          itemsTagged    = 0;
    size_t          itemsSkipped   = 0;
    size_t          itemsDeduped   = 0;   // tagged via hash-cache, NOT re-extracted/re-scanned
    size_t          totalFindings  = 0;
    size_t          totalVerified  = 0;
    size_t          failures       = 0;
    // Resolved at run start (from extraArgs). When verifyOff is true the
    // per-item finding logs suppress "verified=N" since the count is
    // always zero by definition -- a single "verification: off" line is
    // logged once at run start instead.
    bool            verifyOff      = true;

    // Cross-item finding rows, written to <runDir>\<evidence>-trufflehog.tsv
    // at end of run (unless findingsOutput == None).
    std::vector<FindingRow> allFindings;

    // Hash-dedup state. hashSize == 0 means dedup is disabled (either
    // dedup_by_hash=false, or the volume has no primary-hash type configured,
    // or the X-Ways build doesn't expose XWF_GetHashValue/XWF_GetVSProp).
    DWORD                                    hashSize = 0;
    INT64                                    hashType = -1;
    std::map<std::string /*hash*/, Findings> hashCache;
};
static WorkerCtx*   g_worker      = nullptr;
static HANDLE       g_workerThread = nullptr;
static std::wstring g_lastRunDir;  // set on DONE, used by "Open output folder" button
// True only when the async version probe has confirmed the configured exe
// actually identifies as TruffleHog (PE VERSIONINFO check OR --version banner
// check matched the "trufflehog" needle). Gates the Run button -- analysts
// who Browse to a non-trufflehog binary (e.g. hindsight.exe by mistake) get
// a clear visual signal AND can't accidentally fire a scan with the wrong
// helper.
static bool         g_exeValid     = false;
// Helper-rejection flash state. When g_helperRejected is true, the Version
// readout in the dialog is painted bold red via WM_CTLCOLORSTATIC. While
// g_helperFlashTicks > 0, the colour alternates between bright RGB(220,0,0)
// and dark RGB(140,0,0) every 250 ms via WM_TIMER, then settles solid bright
// red. Cleared on every Browse / WM_INITDIALOG so a fresh validation starts
// from a clean state.
static bool         g_helperRejected   = false;
static int          g_helperFlashTicks = 0;
constexpr UINT_PTR  kHelperFlashTimerId   = 0xC004;
constexpr UINT      kHelperFlashPeriodMs  = 250;
constexpr int       kHelperFlashTickCount = 8;        // 8 * 250 ms = ~2 s
// Lazily-created bold font used for the rejection label. Lives for the
// dialog's lifetime; cleaned up in DllMain DLL_PROCESS_DETACH (or simply
// leaked at process exit, which is harmless for a forensic X-Tension).
static HFONT        g_boldFont     = nullptr;
static const wchar_t* kHelperRejectionMessage = L"Not a valid trufflehog.exe file";
static const wchar_t* kHelperMissingMessage   = L"File not found";

static HFONT EnsureBoldFont(HWND hDlg) {
    if (g_boldFont) return g_boldFont;
    HDC hdc = GetDC(hDlg);
    int dpiY = hdc ? GetDeviceCaps(hdc, LOGPIXELSY) : 96;
    if (hdc) ReleaseDC(hDlg, hdc);
    LOGFONTW lf = {};
    wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"MS Shell Dlg");
    lf.lfHeight = -MulDiv(10, dpiY, 72);
    lf.lfWeight = FW_BOLD;
    g_boldFont = CreateFontIndirectW(&lf);
    return g_boldFont;
}

// Loaded once on first dialog open; reused across dialogs in the same DLL
// load. Leaked at DLL unload (harmless one-time GDI; mirrors xways-updater).
static HICON g_titleIconSmall = nullptr;
static HICON g_titleIconBig   = nullptr;

// Apply the title-bar icon from hog.ico (sits next to the DLL).
// Same pattern as xways-updater -- LoadImageW with LR_LOADFROMFILE so the
// .ico doesn't need to be RC-embedded; analysts can swap or update the
// file without rebuilding the DLL. Logs once on first miss for debug.
static void ApplyTitleIcon(HWND hDlg) {
    if (!g_titleIconSmall && !g_titleIconBig) {
        std::wstring iconPath = GetSelfDirectory() + L"\\hog.ico";
        if (FileExists(iconPath)) {
            g_titleIconSmall = (HICON)LoadImageW(nullptr, iconPath.c_str(),
                IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
            g_titleIconBig   = (HICON)LoadImageW(nullptr, iconPath.c_str(),
                IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
            if (!g_titleIconSmall && !g_titleIconBig) {
                Log(L"hog.ico present but LoadImageW failed: " + iconPath);
            }
        } else {
            static bool warned = false;
            if (!warned) {
                Log(L"hog.ico not found at " + iconPath +
                    L" -- drop a 16x16+32x32 .ico there to set the title icon (no rebuild needed).");
                warned = true;
            }
        }
    }
    if (g_titleIconSmall) SendMessageW(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)g_titleIconSmall);
    if (g_titleIconBig)   SendMessageW(hDlg, WM_SETICON, ICON_BIG,   (LPARAM)g_titleIconBig);
}

// Activate the in-dialog rejection display: bold red label, flashing for
// ~2 s then solid bright red, Run button disabled, and the rejected path
// echoed into the path edit so the analyst sees what was rejected. Use
// ClearHelperRejection() when a fresh validation succeeds. labelText lets
// callers distinguish identity-rejection from file-not-found while reusing
// the same flash/disable/log machinery.
static void ShowHelperRejection(HWND hDlg, const std::wstring& rejectedPath,
                                const std::wstring& detail,
                                const wchar_t* labelText) {
    g_helperRejected   = true;
    g_helperFlashTicks = kHelperFlashTickCount;
    g_exeValid         = false;

    EnsureBoldFont(hDlg);
    HWND hVer = GetDlgItem(hDlg, IDC_LABEL_TOOL_VERSION);
    HWND hRun = GetDlgItem(hDlg, IDC_BTN_RUN);

    SetDlgItemTextW(hDlg, IDC_EDIT_TOOL_BIN, rejectedPath.c_str());
    SetDlgItemTextW(hDlg, IDC_LABEL_TOOL_VERSION, labelText);
    if (hVer && g_boldFont) SendMessageW(hVer, WM_SETFONT, (WPARAM)g_boldFont, TRUE);

    // Restart the flash timer cleanly even if a prior rejection's timer was
    // still running -- SetTimer with an existing id resets the countdown.
    SetTimer(hDlg, kHelperFlashTimerId, kHelperFlashPeriodMs, nullptr);
    if (hVer) InvalidateRect(hVer, nullptr, TRUE);
    if (hRun) EnableWindow(hRun, FALSE);

    // Log line carries the detail for forensic-trail purposes (no MessageBox).
    Log(L"helper-exe REJECTED (" + rejectedPath + L") -- " + detail);
}

// Clear the rejection display and restore the Version label to the dialog's
// default font/colour. Idempotent -- safe to call whether or not a rejection
// is active (always restores the default font so the bold-red state is wiped
// even after the flash timer has stopped on its own).
static void ClearHelperRejection(HWND hDlg) {
    if (g_helperRejected) {
        g_helperRejected   = false;
        g_helperFlashTicks = 0;
        KillTimer(hDlg, kHelperFlashTimerId);
    }
    HWND hVer = GetDlgItem(hDlg, IDC_LABEL_TOOL_VERSION);
    if (hVer) {
        // Restore to the dialog's font. WM_GETFONT can return NULL when no
        // application font was set (dialog inherits the system font); in
        // that case pass NULL to WM_SETFONT, which resets the static to the
        // system default. Without this fallback, a system-font dialog would
        // leave the Version label stuck in g_boldFont after a clear.
        HFONT base = (HFONT)SendMessageW(hDlg, WM_GETFONT, 0, 0);
        SendMessageW(hVer, WM_SETFONT, (WPARAM)base, TRUE);
        InvalidateRect(hVer, nullptr, TRUE);
    }
}

static void PostStatus(HWND hDlg, const std::wstring& s) {
    if (!hDlg) return;
    size_t bytes = (s.size() + 1) * sizeof(wchar_t);
    wchar_t* buf = (wchar_t*)malloc(bytes);
    if (!buf) return;
    memcpy(buf, s.c_str(), bytes);
    if (!PostMessageW(hDlg, WM_APP_STATUS, 0, (LPARAM)buf)) free(buf);
}

static void PostProgress(HWND hDlg, int permille) {
    if (hDlg) PostMessageW(hDlg, WM_APP_PROGRESS, (WPARAM)permille, 0);
}

static void PostMarquee(HWND hDlg, bool on) {
    if (hDlg) PostMessageW(hDlg, WM_APP_MARQUEE, (WPARAM)(on ? 1 : 0), 0);
}

// =============================================================================
//  TruffleHog invocation per item
// =============================================================================
static void RecordHit(LONG nItemID, const std::wstring& fullPath,
                      const Findings& fx, const Settings& s) {
    // One report-table entry per detector class. Splitting by detector makes
    // triage in the Report Tables panel navigable -- "trufflehog: AWS",
    // "trufflehog: GitHub", etc. -- vs. dumping everything into one bucket.
    // Prefer XWF_Label (21.7 SR-4+) for the dedup-call API; fall back to
    // XWF_AddToReportTable on older hosts.
    if (s.addToReportTable && (XWF_Label || XWF_AddToReportTable)) {
        for (const auto& det : fx.detectors) {
            std::wstring tbl = L"trufflehog: "; tbl += det;
            if (XWF_Label)
                XWF_Label(nItemID, tbl.c_str(), 0);
            else
                XWF_AddToReportTable(nItemID, tbl.c_str(), 0);
        }
    }
    if (s.addComment && XWF_AddComment) {
        std::wstring detList; bool first = true;
        for (const auto& d : fx.detectors) {
            if (!first) detList += L", ";
            detList += d; first = false;
        }
        size_t verified = fx.verifiedCount();
        INT64  firstLn = fx.firstLine();
        std::wstring note = L"["; note += NAME; note += L"] ";
        note += FormatW(L"%zu finding(s)", fx.total());
        if (verified > 0) note += FormatW(L", %zu verified", verified);
        if (firstLn > 0)  note += FormatW(L", first @ line %lld", (long long)firstLn);
        if (!detList.empty()) { note += L" \x2014 "; note += detList; }
        if (!fullPath.empty()) { note += L" @ "; note += fullPath; }
        XWF_AddComment(nItemID, note.c_str(), COMMENT_APPEND);
    }
}

// Build the trufflehog command line for a given target path (file or dir),
// folding in all relevant Settings flags. Used by ProcessBatch so the
// per-item and per-batch code paths share one flag-building source.
static std::wstring BuildTrufflehogCmd(const Settings& s,
                                       const std::wstring& target,
                                       const std::wstring& outJsonl,
                                       const std::wstring& errLog) {
    std::wstring flags;
    // Verification policy. ALWAYS emit --no-verification unless the
    // analyst put an opt-in flag in Extra arguments. The cfg key
    // `verify_mode=` is IGNORED at run time (see LoadCfg) -- it was a
    // footgun: a stale cfg could silently flip behaviour to live
    // verification with no visual cue. Opt-in is now SOLELY via Extra
    // arguments (--only-verified or --no-verification). s.verifyMode is
    // forced to None on cfg load.
    std::wstring extrasLower = ToLowerW(s.extraArgs);
    bool extrasOptInVerify   = extrasLower.find(L"--only-verified")   != std::wstring::npos;
    bool extrasExplicitNoVer = extrasLower.find(L"--no-verification") != std::wstring::npos;
    if (!extrasExplicitNoVer && !extrasOptInVerify)
        flags += L" --no-verification";
    if (s.forceSkipBinaries)         flags += L" --force-skip-binaries";
    if (!s.filterEntropy.empty())  { flags += L" --filter-entropy="; flags += s.filterEntropy; }
    if (!s.includeDetectors.empty()) { flags += L" --include-detectors="; flags += s.includeDetectors; }
    if (!s.excludeDetectors.empty()) { flags += L" --exclude-detectors="; flags += s.excludeDetectors; }
    // Custom-detector pack (loads YAML patterns on top of built-ins).
    // Path is quoted because it can contain spaces (typical Windows install).
    std::wstring customCfg = ResolveCustomConfigPath(s);
    if (!customCfg.empty()) { flags += L" --config=\""; flags += customCfg; flags += L"\""; }
    if (s.concurrency > 0) flags += FormatW(L" --concurrency=%d", s.concurrency);
    // TruffleHog's --log-level is no longer a dedicated dialog control --
    // analysts pass it in extra_args (e.g. "--log-level=-1") if they want
    // to override the default verbosity.
    if (!s.extraArgs.empty()) { flags += L" "; flags += s.extraArgs; }

    return L"cmd.exe /C \""
         + std::wstring(L"\"") + s.trufflehogExe + L"\""
         + L" filesystem --json --no-update"
         + flags
         + L" \"" + target + L"\""
         + L" > \"" + outJsonl + L"\""
         + L" 2> \"" + errLog + L"\""
         + L"\"";
}

// Parse the leading "<id>_" prefix of a basename into LONG itemID. Returns
// -1 if the basename doesn't start with digits followed by '_'.
static LONG ParseItemIdFromBasename(const std::wstring& base) {
    size_t i = 0;
    while (i < base.size() && base[i] >= L'0' && base[i] <= L'9') ++i;
    if (i == 0 || i >= base.size() || base[i] != L'_') return -1;
    try { return std::stol(base.substr(0, i)); } catch (...) { return -1; }
}

// Map a trufflehog SourceMetadata.Data.Filesystem.file path back to the
// originating X-Ways item ID via our extracted-filename convention
// (chunk-dir/<id>_<safeleaf>). Returns -1 if the basename doesn't match
// the convention -- finding will be dropped for tag/CSV purposes.
static LONG ParseItemIdFromFilePath(const std::wstring& filePath) {
    size_t slash = filePath.find_last_of(L"/\\");
    std::wstring base = (slash == std::wstring::npos) ? filePath : filePath.substr(slash + 1);
    return ParseItemIdFromBasename(base);
}

// Parse the prefilter-extensions CSV (e.g. "jpg, png,MP4") into a set of
// lowercase extensions with no leading dot. Built once per run.
static std::set<std::wstring> ParseExtensionSet(const std::wstring& csv) {
    std::set<std::wstring> out;
    std::wstring cur;
    for (size_t i = 0; i <= csv.size(); ++i) {
        wchar_t c = (i == csv.size()) ? L',' : csv[i];
        if (c == L',' || c == L';' || c == L' ' || c == L'\t') {
            std::wstring trimmed = TrimW(cur);
            if (!trimmed.empty()) {
                if (trimmed[0] == L'.') trimmed.erase(0, 1);
                out.insert(ToLowerW(trimmed));
            }
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    return out;
}

// Returns lowercase extension (no dot) for "foo.tar.GZ" -> "gz". Empty if
// no dot or trailing-dot file.
static std::wstring LeafExtensionLower(const std::wstring& leaf) {
    size_t dot = leaf.find_last_of(L'.');
    if (dot == std::wstring::npos || dot + 1 >= leaf.size()) return {};
    return ToLowerW(leaf.substr(dot + 1));
}

static bool ShouldScan(LONG nItemID, INT64 size, const Settings& s,
                       const std::set<std::wstring>& prefilterExt) {
    if (XWF_GetItemInformation) {
        BOOL valid = FALSE;
        LONG flags = (LONG)XWF_GetItemInformation(nItemID, XWF_ITEM_INFO_FLAGS, &valid);
        if (valid && (flags & XWF_ITEM_INFO_FLAG_DIRECTORY)) return false;
    }
    INT64 maxBytes = s.maxSizeMiB > 0 ? s.maxSizeMiB * 1024LL * 1024LL : INT64_MAX;
    if (size < s.minSizeBytes || size > maxBytes) return false;
    if (!prefilterExt.empty()) {
        const wchar_t* nm = XWF_GetItemName ? XWF_GetItemName(nItemID) : nullptr;
        if (nm && *nm) {
            std::wstring ext = LeafExtensionLower(nm);
            if (!ext.empty() && prefilterExt.count(ext)) return false;
        }
    }
    return true;
}

// Build a status line "[N/M]  <task>: <leaf>" with per-stage task name. The
// task vocabulary is fixed (extracting / scanning / parsing); the dialog's
// status label gets refreshed at each stage so the analyst sees the worker
// is alive even when one item takes a few seconds.
static void PostStageStatus(WorkerCtx* w, size_t idx, size_t total,
                            const wchar_t* task, const std::wstring& leaf) {
    std::wstring trimmed = leaf;
    if (trimmed.size() > 64) trimmed = L"\x2026" + trimmed.substr(trimmed.size() - 60);
    PostStatus(w->hDlg, FormatW(L"[%zu/%zu]  %s: %s",
                                idx, total, task,
                                trimmed.empty() ? L"item" : trimmed.c_str()));
}

// Recursively delete a directory. Used to clean up per-chunk extraction
// dirs after the batch has been scanned (skipped when keep_extracted=true).
static void RecursiveDeleteDir(const std::wstring& dir) {
    std::wstring search = dir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) { RemoveDirectoryW(dir.c_str()); return; }
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring child = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            RecursiveDeleteDir(child);
        } else {
            SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(child.c_str());
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    RemoveDirectoryW(dir.c_str());
}

// Tag one item with its accumulated findings + push CSV rows + bump
// per-run counters. Shared by the batch parser.
static void TagItemFromFindings(WorkerCtx* w, LONG itemID, Findings& fx) {
    if (fx.rows.empty()) return;
    size_t verified = fx.verifiedCount();
    const wchar_t* nm = XWF_GetItemName ? XWF_GetItemName(itemID) : nullptr;
    std::wstring leaf     = (nm && *nm) ? std::wstring(nm) : std::wstring();
    std::wstring fullPath = BuildItemFullPath(itemID);
    // Format: "findings=N: <full path>"   (verification off; default)
    //         "findings=N verified=M: <full path>"   (verification on)
    // The full path is more useful in triage than the bare item ID and
    // is already resolved here for the FindingRow records below.
    const std::wstring& shown = fullPath.empty() ? leaf : fullPath;
    if (w->verifyOff) {
        LogVerbose(FormatW(L"findings=%zu: %s", fx.total(), shown.c_str()));
    } else {
        LogVerbose(FormatW(L"findings=%zu verified=%zu: %s",
                           fx.total(), verified, shown.c_str()));
    }
    w->totalFindings += fx.total();
    w->totalVerified += verified;
    if ((int)fx.total() < w->s->tagThreshold) return;
    for (const auto& f : fx.rows) {
        FindingRow r;
        r.itemID      = itemID;
        r.name        = leaf;
        r.path        = fullPath;
        r.detector    = f.detector;
        r.verified    = f.verified;
        r.line        = f.line;
        r.raw         = f.raw;
        r.rawV2       = f.rawV2;
        r.redacted    = f.redacted;
        r.decoder     = f.decoder;
        r.description = f.description;
        w->allFindings.push_back(std::move(r));
    }
    RecordHit(itemID, fullPath, fx, *w->s);
    ++w->itemsTagged;
}

// Process one chunk of items: extract all, run trufflehog ONCE on the
// chunk dir, parse the consolidated JSONL, map findings back to item IDs
// via the extracted-filename convention (<id>_<safeleaf>), tag.
//
// itemsProcessedSoFar is the running total used for the progress bar +
// status line; the function advances it as items are processed.
static void ProcessBatch(WorkerCtx* w,
                         const std::vector<LONG>& chunkIds,
                         size_t chunkIdx,
                         size_t totalItems,
                         size_t& itemsProcessedSoFar,
                         const std::set<std::wstring>& prefilterExt) {
    if (chunkIds.empty()) return;
    HWND hDlg = w->hDlg;

    // Per-chunk subdir under in/ so cleanup is one RemoveDirectoryW call
    // and the basename namespace stays isolated per batch.
    std::wstring chunkInDir = w->inDir + L"\\chunk-" + std::to_wstring(chunkIdx);
    if (!EnsureDirectoryExists(chunkInDir)) {
        Log(L"failed to create chunk dir: " + chunkInDir);
        w->failures += chunkIds.size();
        return;
    }

    // ---- Phase 1: extract every item in the chunk that passes the gate.
    //   With dedup_by_hash on, we first ask X-Ways for the item's primary
    //   hash; if we've already scanned an item with the same hash earlier
    //   in this run, we tag THIS item with the cached findings and skip
    //   the extract + scan (saves the I/O and trufflehog work entirely).
    //
    //   extractedHashes[id] = hash bytes so Phase 3 can populate the cache
    //   AFTER trufflehog returns findings for those items.
    std::vector<LONG> extractedIds; extractedIds.reserve(chunkIds.size());
    std::map<LONG, std::string> extractedHashes;
    for (LONG id : chunkIds) {
        ++w->itemsSeen;
        ++itemsProcessedSoFar;
        if (w->cancelRequested.load()) break;
        if (XWF_ShouldStop && XWF_ShouldStop()) { w->cancelRequested.store(true); break; }

        INT64 size = XWF_GetItemSize ? XWF_GetItemSize(id) : 0;
        if (!ShouldScan(id, size, *w->s, prefilterExt)) {
            ++w->itemsSkipped;
            continue;
        }

        // Dedup check: if this item's hash matches one we've already scanned,
        // tag with the cached findings and move on -- no extract, no scan.
        std::string hashKey;
        if (w->hashSize > 0) {
            hashKey = QueryItemHash(id, w->hashSize);
            if (!hashKey.empty()) {
                auto it = w->hashCache.find(hashKey);
                if (it != w->hashCache.end()) {
                    Findings copy = it->second;   // local copy: TagItemFromFindings doesn't mutate, but be defensive
                    TagItemFromFindings(w, id, copy);
                    ++w->itemsDeduped;
                    {
                        std::wstring p = BuildItemFullPath(id);
                        if (p.empty()) {
                            const wchar_t* nmd = XWF_GetItemName ? XWF_GetItemName(id) : nullptr;
                            p = (nmd && *nmd) ? std::wstring(nmd) : L"(unknown)";
                        }
                        LogVerbose(L"dedup hit (skipped extract+scan): " + p);
                    }
                    continue;
                }
            }
        }

        const wchar_t* nm = XWF_GetItemName ? XWF_GetItemName(id) : nullptr;
        std::wstring leaf = (nm && *nm) ? std::wstring(nm) : L"item";
        PostStageStatus(w, itemsProcessedSoFar, totalItems, L"Extracting", leaf);

        HANDLE hItem = XWF_OpenItem ? XWF_OpenItem(w->ctx->hVolume, id, 0) : nullptr;
        if (!hItem || hItem == INVALID_HANDLE_VALUE) { ++w->failures; continue; }

        wchar_t idBuf[32]; swprintf_s(idBuf, L"%ld_", id);
        std::wstring destPath = chunkInDir + L"\\" + std::wstring(idBuf) + SafeLeaf(leaf);
        if (!ExtractItemToFile(hItem, size, destPath)) {
            if (XWF_Close) XWF_Close(hItem);
            std::wstring p = BuildItemFullPath(id);
            if (p.empty()) p = leaf;  // leaf already resolved above
            // Gated on the "Verbose X-Tension log" checkbox -- on a noisy
            // case (junk files, restricted streams, sparse files) this
            // can fire hundreds of times. The total failure count is
            // always carried in the end-of-run summary line.
            LogVerbose(L"extract failed: " + p);
            ++w->failures;
            continue;
        }
        if (XWF_Close) XWF_Close(hItem);
        ++w->itemsScanned;
        extractedIds.push_back(id);
        if (!hashKey.empty()) extractedHashes[id] = hashKey;
    }

    if (extractedIds.empty()) {
        // Nothing made it through the gate. Drop the empty chunk dir.
        if (!w->s->keepExtracted) RecursiveDeleteDir(chunkInDir);
        return;
    }

    // ---- Phase 2: ONE trufflehog invocation on the chunk dir.
    PostStageStatus(w, itemsProcessedSoFar, totalItems,
                    FormatW(L"Scanning batch %zu (%zu items)", chunkIdx, extractedIds.size()).c_str(),
                    L"");
    std::wstring chunkOutJsonl = w->outDir + L"\\chunk-" + std::to_wstring(chunkIdx) + L".jsonl";
    std::wstring chunkErrLog   = w->outDir + L"\\chunk-" + std::to_wstring(chunkIdx) + L".err";
    std::wstring cmd = BuildTrufflehogCmd(*w->s, chunkInDir, chunkOutJsonl, chunkErrLog);

    DWORD exitCode = 0;
    if (!RunCommand(cmd, w->runDir, exitCode)) {
        Log(FormatW(L"batch %zu: trufflehog subprocess failed", chunkIdx));
        ++w->failures;
        if (!w->s->keepExtracted) RecursiveDeleteDir(chunkInDir);
        return;
    }

    // ---- Phase 3: parse the consolidated JSONL, map findings back to
    //               originating item IDs, tag each item.
    std::string jsonl;
    if (!ReadWholeFile(chunkOutJsonl, jsonl) || jsonl.empty()) {
        if (!w->s->keepExtracted) RecursiveDeleteDir(chunkInDir);
        return;
    }
    PostStageStatus(w, itemsProcessedSoFar, totalItems,
                    FormatW(L"Parsing batch %zu findings", chunkIdx).c_str(), L"");

    std::map<LONG, Findings> findingsByItem;
    size_t lineStart = 0;
    for (size_t i = 0; i <= jsonl.size(); ++i) {
        if (i != jsonl.size() && jsonl[i] != '\n') continue;
        if (i > lineStart) {
            size_t end = i;
            while (end > lineStart && (jsonl[end-1] == '\r' || isspace((unsigned char)jsonl[end-1]))) --end;
            if (end > lineStart && jsonl[lineStart] == '{') {
                std::string ln(jsonl, lineStart, end - lineStart);
                std::string det = ExtractJsonString(ln, "DetectorName");
                if (!det.empty()) {
                    std::string fileStr = ExtractJsonString(ln, "file");
                    LONG itemID = ParseItemIdFromFilePath(Utf8ToWide(fileStr));
                    if (itemID >= 0) {
                        Finding f;
                        f.detector    = Utf8ToWide(ResolveDetectorLabel(ln, det));
                        f.verified    = ExtractJsonBoolTrue(ln, "Verified");
                        f.line        = ExtractJsonNumber(ln, "line");
                        f.raw         = Utf8ToWide(ExtractJsonString(ln, "Raw"));
                        f.rawV2       = Utf8ToWide(ExtractJsonString(ln, "RawV2"));
                        f.redacted    = Utf8ToWide(ExtractJsonString(ln, "Redacted"));
                        f.decoder     = Utf8ToWide(ExtractJsonString(ln, "DecoderName"));
                        f.description = Utf8ToWide(ExtractJsonString(ln, "DetectorDescription"));
                        if (f.redacted.empty()) f.redacted = f.raw;
                        auto& fx = findingsByItem[itemID];
                        fx.detectors.insert(f.detector);
                        fx.rows.push_back(std::move(f));
                    }
                }
            }
        }
        lineStart = i + 1;
    }
    for (auto& kv : findingsByItem) {
        TagItemFromFindings(w, kv.first, kv.second);
        // Cache the findings under the item's hash so later items with the
        // same content (think: the same .aws/credentials backed up under
        // multiple user profiles) can be tagged without re-scanning.
        auto hashIt = extractedHashes.find(kv.first);
        if (hashIt != extractedHashes.end() && !hashIt->second.empty()) {
            w->hashCache[hashIt->second] = kv.second;
        }
    }

    // ---- Phase 4: cleanup.
    if (!w->s->keepExtracted) RecursiveDeleteDir(chunkInDir);
}

// =============================================================================
//  Consolidated findings XLSX at end of run
// =============================================================================
//   findings.xlsx -- a true Office Open XML spreadsheet, not a renamed CSV.
//   File name = <evidence-name>-trufflehog.xlsx so multi-evidence cases keep
//   distinct files alongside each other in the run dir.
//
//   Mode (Settings.findingsOutput):
//     None     -> file not written
//     Redacted -> Raw / RawV2 columns are partial-masked; Redacted column
//                 stays as-is (it's already safe). Other metadata stays.
//     Full     -> Raw / RawV2 carried verbatim from the JSONL.
//
//   Same exposure as the per-chunk .jsonl files in run\out\ -- the XLSX is
//   the analyst-friendly consolidated form, with a frozen header row and
//   an auto-filter wired across the data range.
//
//   Implementation note: XLSX = ZIP of XML parts. We write the archive
//   STORE-ONLY (no compression) so the X-Tension keeps zero third-party
//   dependencies. Findings files are typically a few MB; analysts who open
//   them already have a spreadsheet app that handles the size fine. If a
//   future version wants compressed XLSX, vendor a minimal deflate (miniz)
//   here and switch ZipAddStored -> ZipAddDeflated.

// Pull the evidence-object title via XWF_GetEvObjProp (prop 7 = ExtObjTitle,
// "HD123, Partition 2"). Sanitized to filesystem-safe ASCII for use in a
// file name. Falls back to "evidence" if X-Ways doesn't supply a title.
static std::wstring GetEvidenceTitleForFile(HANDLE hEvidence) {
    std::wstring title;
    if (XWF_GetEvObjProp && hEvidence) {
        wchar_t buf[MAX_PATH] = {0};
        XWF_GetEvObjProp(hEvidence, /*nPropType=*/7, buf);
        if (!buf[0]) {
            // Property 7 (ExtObjTitle) sometimes empty for top-level disk EOs;
            // try 6 (ObjTitle) as a fallback.
            XWF_GetEvObjProp(hEvidence, /*nPropType=*/6, buf);
        }
        title = buf;
    }
    if (title.empty()) title = L"evidence";
    // Sanitize: strip path-illegal characters; collapse runs of whitespace
    // and commas (common in "HD123, Partition 2" titles) to single
    // underscores so the filename stays readable.
    std::wstring out; out.reserve(title.size());
    wchar_t prev = 0;
    for (wchar_t c : title) {
        bool illegal = (c == L'\\' || c == L'/' || c == L':' || c == L'*' ||
                        c == L'?'  || c == L'"' || c == L'<' || c == L'>' ||
                        c == L'|'  || c == L',');
        if (illegal || iswspace(c)) {
            if (prev != L'_') out.push_back(L'_');
            prev = L'_';
        } else {
            out.push_back(c);
            prev = c;
        }
    }
    while (!out.empty() && out.back() == L'_') out.pop_back();
    if (out.empty()) out = L"evidence";
    return out;
}

// ----- Minimal XLSX writer (store-only ZIP) --------------------------------

static uint32_t Crc32(const void* data, size_t len) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    const auto* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i)
        crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

static void ZipAppend16(std::string& s, uint16_t v) {
    s.push_back((char)(v & 0xFF));
    s.push_back((char)((v >> 8) & 0xFF));
}
static void ZipAppend32(std::string& s, uint32_t v) {
    s.push_back((char)(v & 0xFF));
    s.push_back((char)((v >> 8) & 0xFF));
    s.push_back((char)((v >> 16) & 0xFF));
    s.push_back((char)((v >> 24) & 0xFF));
}

struct ZipEntry {
    std::string name;
    uint32_t    crc32 = 0;
    uint32_t    size  = 0;
    uint32_t    lfhOffset = 0;
};

// Append a stored (method=0) entry to `archive` and record metadata for the
// central directory pass.
static void ZipAddStored(std::string& archive, std::vector<ZipEntry>& entries,
                         const std::string& name, const std::string& data) {
    ZipEntry e;
    e.name      = name;
    e.crc32     = Crc32(data.data(), data.size());
    e.size      = (uint32_t)data.size();
    e.lfhOffset = (uint32_t)archive.size();
    // Local file header.
    ZipAppend32(archive, 0x04034b50u);
    ZipAppend16(archive, 20);             // version needed (2.0)
    ZipAppend16(archive, 0);              // general purpose flag
    ZipAppend16(archive, 0);              // method = STORE
    ZipAppend16(archive, 0);              // mod time
    ZipAppend16(archive, 0);              // mod date
    ZipAppend32(archive, e.crc32);
    ZipAppend32(archive, e.size);         // compressed size = uncompressed (stored)
    ZipAppend32(archive, e.size);
    ZipAppend16(archive, (uint16_t)name.size());
    ZipAppend16(archive, 0);              // extra length
    archive.append(name);
    archive.append(data);
    entries.push_back(std::move(e));
}

// Finalise: write the central directory and end-of-central-directory record.
static void ZipFinish(std::string& archive, const std::vector<ZipEntry>& entries) {
    uint32_t cdOffset = (uint32_t)archive.size();
    for (const auto& e : entries) {
        ZipAppend32(archive, 0x02014b50u);   // central dir signature
        ZipAppend16(archive, 20);            // version made by
        ZipAppend16(archive, 20);            // version needed
        ZipAppend16(archive, 0);             // gp flag
        ZipAppend16(archive, 0);             // method
        ZipAppend16(archive, 0);             // mod time
        ZipAppend16(archive, 0);             // mod date
        ZipAppend32(archive, e.crc32);
        ZipAppend32(archive, e.size);
        ZipAppend32(archive, e.size);
        ZipAppend16(archive, (uint16_t)e.name.size());
        ZipAppend16(archive, 0);             // extra len
        ZipAppend16(archive, 0);             // comment len
        ZipAppend16(archive, 0);             // disk number start
        ZipAppend16(archive, 0);             // internal attrs
        ZipAppend32(archive, 0);             // external attrs
        ZipAppend32(archive, e.lfhOffset);
        archive.append(e.name);
    }
    uint32_t cdSize = (uint32_t)archive.size() - cdOffset;
    ZipAppend32(archive, 0x06054b50u);       // EOCD signature
    ZipAppend16(archive, 0);                 // disk number
    ZipAppend16(archive, 0);                 // disk with CD
    ZipAppend16(archive, (uint16_t)entries.size());
    ZipAppend16(archive, (uint16_t)entries.size());
    ZipAppend32(archive, cdSize);
    ZipAppend32(archive, cdOffset);
    ZipAppend16(archive, 0);                 // comment len
}

// XML text escape. Input is UTF-8; multi-byte sequences (>= 0x80) pass
// through unchanged. Control chars other than \t \n \r are dropped (XML 1.0
// forbids them).
static std::string XmlEscape(const std::string& in) {
    std::string out; out.reserve(in.size() + 16);
    for (unsigned char c : in) {
        switch (c) {
        case '&':  out += "&amp;";  break;
        case '<':  out += "&lt;";   break;
        case '>':  out += "&gt;";   break;
        case '"':  out += "&quot;"; break;
        case '\'': out += "&apos;"; break;
        case '\t': out += "&#9;";   break;
        case '\n': out += "&#10;";  break;
        case '\r': out += "&#13;";  break;
        default:
            if (c >= 0x20) out += (char)c;
            // else: drop disallowed control char
            break;
        }
    }
    return out;
}

// 0-based column index -> spreadsheet letters (0->A, 25->Z, 26->AA, ...).
static std::string XlsxColumnLetter(size_t idx) {
    char tmp[8]; int i = 0;
    size_t n = idx + 1;            // 1-based
    while (n > 0 && i < 7) {
        n -= 1;
        tmp[i++] = (char)('A' + (n % 26));
        n /= 26;
    }
    std::string out; out.reserve(i);
    while (i > 0) out.push_back(tmp[--i]);
    return out;
}

// Build the sheet1.xml payload from the row matrix. Row 0 is the header.
// Inline strings everywhere (no shared-string table). Freezes the header
// row and wires an auto-filter across the data range.
static std::string BuildSheetXml(const std::vector<std::vector<std::string>>& rows) {
    std::string s;
    s.reserve(rows.size() * 256 + 1024);
    s += "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n";
    s += "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">";
    s += "<sheetViews><sheetView workbookViewId=\"0\">";
    s += "<pane ySplit=\"1\" topLeftCell=\"A2\" state=\"frozen\" activePane=\"bottomLeft\"/>";
    s += "</sheetView></sheetViews>";
    s += "<sheetData>";
    char numbuf[32];
    for (size_t r = 0; r < rows.size(); ++r) {
        sprintf_s(numbuf, "%zu", r + 1);
        s += "<row r=\""; s += numbuf; s += "\">";
        for (size_t c = 0; c < rows[r].size(); ++c) {
            s += "<c r=\""; s += XlsxColumnLetter(c); s += numbuf;
            s += "\" t=\"inlineStr\"><is><t>";
            s += XmlEscape(rows[r][c]);
            s += "</t></is></c>";
        }
        s += "</row>";
    }
    s += "</sheetData>";
    if (!rows.empty() && !rows[0].empty()) {
        sprintf_s(numbuf, "%zu", rows.size());
        s += "<autoFilter ref=\"A1:";
        s += XlsxColumnLetter(rows[0].size() - 1);
        s += numbuf; s += "\"/>";
    }
    s += "</worksheet>";
    return s;
}

// Write a single-sheet XLSX with the given rows. Returns false on file I/O
// failure (logged by caller).
static bool WriteXlsx(const std::wstring& path,
                      const std::vector<std::vector<std::string>>& rows,
                      const std::string& sheetName = "Findings") {
    static const std::string kContentTypes =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
        "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
        "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
        "<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>"
        "<Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>"
        "</Types>";
    static const std::string kRootRels =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>"
        "</Relationships>";
    std::string workbook =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\""
        " xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">"
        "<sheets><sheet name=\"";
    workbook += XmlEscape(sheetName);
    workbook += "\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>";
    static const std::string kWorkbookRels =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>"
        "</Relationships>";

    std::string archive;
    archive.reserve(rows.size() * 256 + 4096);
    std::vector<ZipEntry> entries;
    ZipAddStored(archive, entries, "[Content_Types].xml",         kContentTypes);
    ZipAddStored(archive, entries, "_rels/.rels",                 kRootRels);
    ZipAddStored(archive, entries, "xl/workbook.xml",             workbook);
    ZipAddStored(archive, entries, "xl/_rels/workbook.xml.rels",  kWorkbookRels);
    ZipAddStored(archive, entries, "xl/worksheets/sheet1.xml",    BuildSheetXml(rows));
    ZipFinish(archive, entries);

    FILE* fp = nullptr;
    if (_wfopen_s(&fp, path.c_str(), L"wb") != 0 || !fp) return false;
    size_t written = fwrite(archive.data(), 1, archive.size(), fp);
    fclose(fp);
    return written == archive.size();
}

// Partial-mask a Raw secret for the "Redacted" TSV mode. Keeps the first
// and last 3 characters and replaces the middle with '*'. For very short
// strings (< 8 chars), masks all but the first char.
static std::wstring PartialMask(const std::wstring& raw) {
    if (raw.empty()) return {};
    if (raw.size() < 8) {
        std::wstring out = raw.substr(0, 1);
        out.append(raw.size() - 1, L'*');
        return out;
    }
    std::wstring out = raw.substr(0, 3);
    out.append(raw.size() - 6, L'*');
    out += raw.substr(raw.size() - 3, 3);
    return out;
}

// Build one rows-matrix (header + N data rows) for a slice of allFindings.
static std::vector<std::vector<std::string>> BuildFindingsRows(
        const WorkerCtx* w, FindingsOutputMode mode, size_t start, size_t end) {
    std::vector<std::vector<std::string>> rows;
    rows.reserve(end - start + 1);
    rows.push_back({"ItemID", "Name", "FullPath", "Detector", "Verified",
                    "Line", "Raw", "RawV2", "Redacted", "Decoder",
                    "DetectorDescription"});
    char buf[64];
    for (size_t i = start; i < end; ++i) {
        const auto& r = w->allFindings[i];
        std::wstring raw   = (mode == FindingsOutputMode::Full) ? r.raw   : PartialMask(r.raw);
        std::wstring rawV2 = (mode == FindingsOutputMode::Full) ? r.rawV2 : PartialMask(r.rawV2);
        sprintf_s(buf, "%ld", r.itemID);
        std::vector<std::string> row;
        row.reserve(11);
        row.emplace_back(buf);
        row.emplace_back(WideToUtf8(r.name));
        row.emplace_back(WideToUtf8(r.path));
        row.emplace_back(WideToUtf8(r.detector));
        row.emplace_back(r.verified ? "true" : "false");
        if (r.line > 0) { sprintf_s(buf, "%lld", (long long)r.line); row.emplace_back(buf); }
        else            { row.emplace_back(""); }
        row.emplace_back(WideToUtf8(raw));
        row.emplace_back(WideToUtf8(rawV2));
        row.emplace_back(WideToUtf8(r.redacted));
        row.emplace_back(WideToUtf8(r.decoder));
        row.emplace_back(WideToUtf8(r.description));
        rows.push_back(std::move(row));
    }
    return rows;
}

static void EmitFindingsXlsx(WorkerCtx* w, FindingsOutputMode mode,
                             HANDLE hEvidence) {
    if (mode == FindingsOutputMode::None) return;
    if (w->allFindings.empty()) {
        LogVerbose(L"findings XLSX: no findings to emit -- skipping file");
        return;
    }
    std::wstring base = GetEvidenceTitleForFile(hEvidence);

    // Effective split size. The dialog/cfg clamp into [1, 1000000] already
    // (Excel's per-sheet limit is 1,048,576; we leave headroom for header +
    // future metadata). Defensive belt-and-braces clamp here too.
    size_t splitRows = (size_t)w->s->findingsRowsPerSheet;
    if (splitRows < 1)        splitRows = 500000;
    if (splitRows > 1000000)  splitRows = 1000000;

    const size_t total    = w->allFindings.size();
    const size_t numFiles = (total + splitRows - 1) / splitRows;
    const wchar_t* modeLabel = (mode == FindingsOutputMode::Full) ? L"FULL raw" : L"redacted";

    for (size_t fileIdx = 0; fileIdx < numFiles; ++fileIdx) {
        const size_t start = fileIdx * splitRows;
        const size_t end   = std::min(start + splitRows, total);

        // Single-file runs keep the un-suffixed name; multi-file runs append
        // -1, -2, ... so analysts can see at a glance that the output split.
        std::wstring path = w->runDir + L"\\" + base + L"-trufflehog";
        if (numFiles > 1) {
            wchar_t suffix[16];
            swprintf_s(suffix, L"-%zu", fileIdx + 1);
            path += suffix;
        }
        path += L".xlsx";

        auto rows = BuildFindingsRows(w, mode, start, end);
        if (!WriteXlsx(path, rows)) {
            Log(L"failed to write findings XLSX: " + path);
            continue;
        }
        Log(FormatW(L"findings XLSX (%s): %zu rows -> %s",
                    modeLabel, end - start, path.c_str()));
    }
    if (numFiles > 1) {
        Log(FormatW(L"findings split: %zu rows across %zu file(s) (split at %zu rows/file)",
                    total, numFiles, splitRows));
    }
}

// =============================================================================
//  Worker thread
// =============================================================================
static unsigned __stdcall WorkerThread(void* arg) {
    auto* w = (WorkerCtx*)arg;
    HWND  hDlg = w->hDlg;

    // Apply the X-Tension verbose flag for this run -- LogVerbose() reads it.
    g_verbose = w->s->verbose;

    // ---- Set up the run-dir tree.
    //   outputBase already includes the X-Tension subfolder (set by
    //   ResolveDefaultOutputBase or by the user via the dialog).
    std::wstring xtRoot = w->s->outputBase;
    if (xtRoot.empty()) {
        std::wstring src;
        xtRoot = ResolveDefaultOutputBase(w->ctx->hEvidence, src);
        Log(L"output base: " + xtRoot + L"  (" + src + L")");
    }
    if (!EnsureDirectoryExists(xtRoot)) {
        PostStatus(hDlg, L"Failed to create output root: " + xtRoot);
        PostMessageW(hDlg, WM_APP_DONE, 0, 0);
        return 1;
    }
    w->runDir = CreateUniqueRunDir(xtRoot);
    if (w->runDir.empty()) {
        PostStatus(hDlg, L"Failed to create run dir under: " + xtRoot);
        PostMessageW(hDlg, WM_APP_DONE, 0, 0);
        return 1;
    }
    w->inDir  = w->runDir + L"\\in";
    w->outDir = w->runDir + L"\\out";
    if (!EnsureDirectoryExists(w->inDir) || !EnsureDirectoryExists(w->outDir)) {
        PostStatus(hDlg, L"Failed to create in/out subdirs under: " + w->runDir);
        PostMessageW(hDlg, WM_APP_DONE, 0, 0);
        return 1;
    }
    g_lastRunDir = w->runDir;
    Log(L"run dir: " + w->runDir);

    // ---- Hash-dedup setup. Query the volume snapshot's primary hash type
    //      once per run; if it resolves to a known type AND dedup_by_hash is
    //      enabled, hashSize > 0 unlocks the cache check inside ProcessBatch.
    if (w->s->dedupByHash && XWF_GetVSProp) {
        INT64 ht = XWF_GetVSProp(XWF_VSPROP_HASHTYPE1, nullptr);
        DWORD hs = HashTypeToSize(ht);
        if (hs > 0) {
            w->hashType = ht;
            w->hashSize = hs;
            Log(FormatW(L"dedup_by_hash: ON (hash type=%lld, %lu-byte cache key)",
                        (long long)ht, (unsigned long)hs));
        } else {
            Log(FormatW(L"dedup_by_hash: OFF (volume has no recognized primary "
                        L"hash type; XWF_VSPROP_HASHTYPE1=%lld). "
                        L"Hash the snapshot first to enable.",
                        (long long)ht));
        }
    } else if (!w->s->dedupByHash) {
        Log(L"dedup_by_hash: OFF (disabled in settings)");
    }

    // Log the resolved custom-detector config so it's visible in the
    // Messages window which extra patterns are in play.
    {
        std::wstring resolved = ResolveCustomConfigPath(*w->s);
        if (!resolved.empty()) Log(L"custom config: " + resolved);
        else                   Log(L"custom config: (none -- built-in detectors only)");
    }

    // Verification policy -- logged once so per-item logs can stay terse.
    // Mirrors BuildTrufflehogCmd's emit-rule exactly: --no-verification is
    // suppressed (i.e. verification is on) iff extras contain
    // --only-verified or --no-verification. Otherwise --no-verification
    // is appended and verification is off.
    {
        std::wstring lo = ToLowerW(w->s->extraArgs);
        bool extrasOnly = lo.find(L"--only-verified")   != std::wstring::npos;
        bool extrasNo   = lo.find(L"--no-verification") != std::wstring::npos;
        w->verifyOff = !extrasOnly;  // --no-verification in extras still = off
        if (w->verifyOff) {
            Log(L"verification: OFF (--no-verification will be passed; "
                L"per-item logs will omit 'verified=N')");
        } else {
            Log(L"verification: ON (--only-verified in extra_args) -- "
                L"outbound network calls to providers WILL happen");
        }
        (void)extrasNo;  // captured for symmetry with BuildTrufflehogCmd; not used here
    }

    // ---- Item set: pre-collected by XT_ProcessItem (filter-respected for
    //      Tools->Run X-Tension, selection-respected for right-click).
    const std::vector<LONG>& ids = w->ctx->items;

    if (ids.empty()) {
        PostStatus(hDlg, L"No items to scan.");
        PostMessageW(hDlg, WM_APP_DONE, 1, 0);
        return 0;
    }

    PostMarquee(hDlg, false);
    SendMessageW(GetDlgItem(hDlg, IDC_PROGRESS_RUN), PBM_SETRANGE32, 0, 1000);
    PostStatus(hDlg, FormatW(L"Scanning %zu item(s) in batches of %d...",
                             ids.size(), w->s->batchChunkSize > 0 ? w->s->batchChunkSize : (int)ids.size()));

    // Parse the prefilter-extensions CSV once; ShouldScan consults it per item.
    std::set<std::wstring> prefilterExt = ParseExtensionSet(w->s->prefilterExtensions);

    // Chunked batch: extract N items, invoke trufflehog ONCE on the chunk,
    // parse + tag. Batches amortise trufflehog's ~2.5s startup cost across
    // N items instead of paying it per item.
    const size_t total = ids.size();
    const size_t chunkSize = w->s->batchChunkSize > 0
        ? std::min<size_t>((size_t)w->s->batchChunkSize, total)
        : total;
    size_t processed = 0;
    size_t chunkIdx = 0;
    for (size_t start = 0; start < total; start += chunkSize) {
        if (w->cancelRequested.load()) break;
        if (XWF_ShouldStop && XWF_ShouldStop()) { w->cancelRequested.store(true); break; }
        size_t end = std::min(start + chunkSize, total);
        std::vector<LONG> chunk(ids.begin() + start, ids.begin() + end);
        ProcessBatch(w, chunk, chunkIdx, total, processed, prefilterExt);
        int permille = (int)((double)end * 1000.0 / (double)total);
        PostProgress(hDlg, permille);
        ++chunkIdx;
    }

    bool cancelled = w->cancelRequested.load();

    // Defensive diagnostic: if dedup was enabled, the volume reported a
    // primary hash type, but we never observed a usable hash on any item,
    // tell the analyst -- they probably enabled dedup expecting it to fire
    // and would otherwise be left wondering why deduped=0.
    if (w->s->dedupByHash && w->hashSize > 0 && w->itemsDeduped == 0 && w->itemsScanned > 0) {
        Log(L"dedup_by_hash: no items had a usable primary hash this run "
            L"(dedup effectively disabled). Run Volume Snapshot Refinement -> "
            L"Compute hash on the snapshot to enable cross-item dedup.");
    }

    // Emit findings XLSX (if mode != None) before posting DONE so analysts
    // pressing "Open output folder" the moment the dialog re-enables see
    // the consolidated file.
    EmitFindingsXlsx(w, w->s->findingsOutput, w->ctx->hEvidence);

    PostStatus(hDlg, FormatW(L"%s: scanned=%zu tagged=%zu deduped=%zu skipped=%zu findings=%zu verified=%zu failures=%zu",
                             cancelled ? L"Cancelled" : L"Done",
                             w->itemsScanned, w->itemsTagged, w->itemsDeduped, w->itemsSkipped,
                             w->totalFindings, w->totalVerified, w->failures));
    Log(FormatW(L"summary: seen=%zu scanned=%zu tagged=%zu deduped=%zu skipped=%zu findings=%zu verified=%zu failures=%zu",
                w->itemsSeen, w->itemsScanned, w->itemsTagged, w->itemsDeduped, w->itemsSkipped,
                w->totalFindings, w->totalVerified, w->failures));
    Log(L"outputs: " + w->runDir);
    PostMessageW(hDlg, WM_APP_DONE, (WPARAM)(cancelled ? 0 : 1), 0);
    return 0;
}

// =============================================================================
//  Dialog plumbing
// =============================================================================
static const int kInputCtlIds[] = {
    IDC_EDIT_TOOL_BIN, IDC_BTN_BROWSE_TOOL,
    IDC_EDIT_MIN_SIZE, IDC_EDIT_MAX_SIZE,
    IDC_CHK_SKIP_BINARIES, IDC_EDIT_FILTER_ENTROPY, IDC_EDIT_PREFILTER_EXT,
    IDC_EDIT_INCLUDE_DETECTORS, IDC_EDIT_EXCLUDE_DETECTORS,
    IDC_COMBO_CONCURRENCY, IDC_EDIT_BATCH_SIZE, IDC_EDIT_EXTRA_ARGS,
    IDC_EDIT_OUTPUT_DIR, IDC_BTN_BROWSE_OUTPUT,
    IDC_CHK_KEEP_EXTRACTED, IDC_CHK_ADD_REPORT_TABLE,
    IDC_EDIT_TAG_THRESHOLD, IDC_CHK_VERBOSE, IDC_CHK_FINDINGS_TSV, IDC_EDIT_SPLIT_ROWS,
    IDC_BTN_RUN, IDCANCEL,
};

static void SetDialogBusy(HWND hDlg, bool busy) {
    HWND hProg = GetDlgItem(hDlg, IDC_PROGRESS_RUN);
    // Progress bar stays VISIBLE in all states (idle pre-Run, animated
    // during the run, full after Done). Just reset to determinate mode and
    // zero on each Run-click; the worker drives PBM_SETPOS afterward.
    if (busy) {
        SendMessageW(hProg, PBM_SETMARQUEE, FALSE, 0);
        LONG_PTR style = GetWindowLongPtrW(hProg, GWL_STYLE);
        SetWindowLongPtrW(hProg, GWL_STYLE, style & ~PBS_MARQUEE);
        SendMessageW(hProg, PBM_SETRANGE32, 0, 1000);
        SendMessageW(hProg, PBM_SETPOS, 0, 0);
        // Allow Cancel during run; it sets cancelRequested.
        EnableWindow(GetDlgItem(hDlg, IDCANCEL), TRUE);
    }
    for (int id : kInputCtlIds) {
        HWND h = GetDlgItem(hDlg, id);
        if (h && id != IDCANCEL) EnableWindow(h, busy ? FALSE : TRUE);
    }
    // About + Open-output stay enabled at all times.
    EnableWindow(GetDlgItem(hDlg, IDC_BTN_ABOUT), TRUE);
    EnableWindow(GetDlgItem(hDlg, IDC_BTN_OPEN_OUTPUT), TRUE);
    // Run button is also gated on exe-validity (the async --version probe
    // must have confirmed the binary is actually TruffleHog). When busy,
    // Run is force-disabled regardless; when idle, it follows g_exeValid.
    EnableWindow(GetDlgItem(hDlg, IDC_BTN_RUN),
                 (!busy && g_exeValid) ? TRUE : FALSE);
}

// Read controls -> Settings struct on Run.
static bool ReadDialogToSettings(HWND hDlg, Settings& s) {
    wchar_t buf[1024];

    GetDlgItemTextW(hDlg, IDC_EDIT_TOOL_BIN, buf, _countof(buf));
    s.trufflehogExe = TrimW(buf);
    if (s.trufflehogExe.empty() || !FileExists(s.trufflehogExe)) {
        MessageBoxW(hDlg, L"trufflehog.exe path is empty or does not exist.\n\nDownload a Windows release from\n  https://github.com/trufflesecurity/trufflehog/releases\nand point this field at the binary.",
                    L"xways-trufflehog", MB_OK | MB_ICONWARNING);
        SetFocus(GetDlgItem(hDlg, IDC_EDIT_TOOL_BIN));
        return false;
    }

    GetDlgItemTextW(hDlg, IDC_EDIT_OUTPUT_DIR, buf, _countof(buf));
    s.outputBase = TrimW(buf);

    GetDlgItemTextW(hDlg, IDC_EDIT_MIN_SIZE, buf, _countof(buf));
    s.minSizeBytes = ParseInt64(buf, 1);
    if (s.minSizeBytes < 0) s.minSizeBytes = 0;

    GetDlgItemTextW(hDlg, IDC_EDIT_MAX_SIZE, buf, _countof(buf));
    s.maxSizeMiB = ParseInt64(buf, 256);
    if (s.maxSizeMiB < 0) s.maxSizeMiB = 0;

    s.forceSkipBinaries = IsDlgButtonChecked(hDlg, IDC_CHK_SKIP_BINARIES) == BST_CHECKED;

    GetDlgItemTextW(hDlg, IDC_EDIT_FILTER_ENTROPY, buf, _countof(buf));
    s.filterEntropy = TrimW(buf);

    GetDlgItemTextW(hDlg, IDC_EDIT_PREFILTER_EXT, buf, _countof(buf));
    s.prefilterExtensions = TrimW(buf);


    GetDlgItemTextW(hDlg, IDC_EDIT_INCLUDE_DETECTORS, buf, _countof(buf));
    s.includeDetectors = TrimW(buf);
    GetDlgItemTextW(hDlg, IDC_EDIT_EXCLUDE_DETECTORS, buf, _countof(buf));
    s.excludeDetectors = TrimW(buf);

    // Concurrency: combobox with item data = int (0=Auto, 1, 2, 4, ...).
    HWND hConcCombo = GetDlgItem(hDlg, IDC_COMBO_CONCURRENCY);
    if (hConcCombo) {
        LRESULT sel = SendMessageW(hConcCombo, CB_GETCURSEL, 0, 0);
        LRESULT data = (sel == CB_ERR) ? 0 : SendMessageW(hConcCombo, CB_GETITEMDATA, sel, 0);
        s.concurrency = (data == CB_ERR) ? 0 : (int)data;
    }

    // Batch size: dialog-side clamp [10, 5000]. cfg can push to 20000.
    // 0 stays a valid cfg-only sentinel for "scan everything in one batch".
    GetDlgItemTextW(hDlg, IDC_EDIT_BATCH_SIZE, buf, _countof(buf));
    int batchEntered = ParseInt(buf, s.batchChunkSize);
    if (batchEntered != 0) {  // preserve 0 if user typed it; otherwise clamp
        if (batchEntered < 10)   batchEntered = 10;
        if (batchEntered > 5000) batchEntered = 5000;
    }
    s.batchChunkSize = batchEntered;

    GetDlgItemTextW(hDlg, IDC_EDIT_EXTRA_ARGS, buf, _countof(buf));
    s.extraArgs = TrimW(buf);

    s.keepExtracted    = IsDlgButtonChecked(hDlg, IDC_CHK_KEEP_EXTRACTED)    == BST_CHECKED;
    // "Add findings" tri-state (BS_AUTO3STATE on IDC_CHK_ADD_REPORT_TABLE):
    //   BST_UNCHECKED     -> neither Report Table nor Comments column
    //   BST_INDETERMINATE -> Report Table only
    //   BST_CHECKED       -> Report Table + Comments column (default)
    // Both underlying Settings fields (addToReportTable, addComment) are
    // preserved so cfg compatibility is unchanged.
    UINT addTri = IsDlgButtonChecked(hDlg, IDC_CHK_ADD_REPORT_TABLE);
    s.addToReportTable = (addTri != BST_UNCHECKED);
    s.addComment       = (addTri == BST_CHECKED);

    GetDlgItemTextW(hDlg, IDC_EDIT_TAG_THRESHOLD, buf, _countof(buf));
    s.tagThreshold = ParseInt(buf, 1);
    if (s.tagThreshold < 1) s.tagThreshold = 1;

    s.verbose = IsDlgButtonChecked(hDlg, IDC_CHK_VERBOSE) == BST_CHECKED;

    // Tri-state findings TSV (BS_AUTO3STATE):
    //   BST_UNCHECKED     -> None
    //   BST_INDETERMINATE -> Redacted
    //   BST_CHECKED       -> Full
    UINT tri = IsDlgButtonChecked(hDlg, IDC_CHK_FINDINGS_TSV);
    s.findingsOutput =
        tri == BST_CHECKED       ? FindingsOutputMode::Full :
        tri == BST_INDETERMINATE ? FindingsOutputMode::Redacted :
                                    FindingsOutputMode::None;

    // Split-rows. Blank field -> use the default 500k (the cue banner already
    // shows that). Out-of-range values clamp into [1, 1000000].
    GetDlgItemTextW(hDlg, IDC_EDIT_SPLIT_ROWS, buf, _countof(buf));
    std::wstring splitStr = TrimW(buf);
    if (splitStr.empty()) {
        s.findingsRowsPerSheet = 500000;
    } else {
        int v = ParseInt(splitStr, 500000);
        if (v < 1)       v = 1;
        if (v > 1000000) v = 1000000;
        s.findingsRowsPerSheet = v;
    }

    return true;
}

// --- Bold font for GROUPBOX section headers --------------------------------
//   The .rc FONT directive carries a single regular-weight font for the whole
//   dialog. We overlay 11pt bold on each GROUPBOX title at WM_INITDIALOG to
//   establish the canonical visual hierarchy (per
//   docs/xtension-dialog-conventions.md). HFONT is cached; one-time GDI leak
//   on DLL unload, no per-open allocation.
static void ApplyGroupTitleFont(HWND hDlg) {
    static HFONT s_groupTitleFont = nullptr;
    if (!s_groupTitleFont) {
        HDC hdc = GetDC(hDlg);
        int dpiY = hdc ? GetDeviceCaps(hdc, LOGPIXELSY) : 96;
        if (hdc) ReleaseDC(hDlg, hdc);
        LOGFONTW lf = {};
        lf.lfWeight  = FW_BOLD;
        lf.lfCharSet = DEFAULT_CHARSET;
        wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"MS Shell Dlg");
        lf.lfHeight  = -MulDiv(11, dpiY, 72);
        s_groupTitleFont = CreateFontIndirectW(&lf);
    }
    if (!s_groupTitleFont) return;
    static const int kGroupIds[] = {
        IDC_GROUP_TOOL, IDC_GROUP_INPUT, IDC_GROUP_VERIFY,
        IDC_GROUP_OPTIONS, IDC_GROUP_OUTPUT, IDC_GROUP_STATUS,
    };
    for (int id : kGroupIds) {
        HWND grp = GetDlgItem(hDlg, id);
        if (grp) SendMessageW(grp, WM_SETFONT, (WPARAM)s_groupTitleFont, TRUE);
    }
}

// --- Cue-banner placeholder hints ------------------------------------------
//   Shown when the edit is empty (TRUE = stay visible while edit has focus
//   too). Conventionally shorter than tooltips; tooltips explain WHY, cue
//   banners hint at the expected FORMAT.
static void ApplyCueBanners(HWND hDlg, const Settings* s) {
    auto cue = [&](int id, const wchar_t* text) {
        SendDlgItemMessageW(hDlg, id, EM_SETCUEBANNER, TRUE, (LPARAM)text);
    };
    cue(IDC_EDIT_TOOL_BIN,          L"Path to trufflehog.exe (v3.x)");
    cue(IDC_EDIT_FILTER_ENTROPY,    L"e.g. 3.0  (blank = off)");
    cue(IDC_EDIT_PREFILTER_EXT,     L"jpg,png,mp4,exe,dll,zip,...");
    cue(IDC_EDIT_INCLUDE_DETECTORS, L"AWS, Github, Slack  (blank = all detectors)");
    cue(IDC_EDIT_EXCLUDE_DETECTORS, L"URI, JDBC  (forensic-noise defaults)");
    // IDC_COMBO_CONCURRENCY is a CBS_DROPDOWNLIST -- no cue banner support.
    cue(IDC_EDIT_BATCH_SIZE,        L"100 (default, 10..5000)");
    // "Hint:" prefix disambiguates the placeholder from a literal-looking
    // command-line fragment -- the cue banner is purely cosmetic (it's an
    // EM_SETCUEBANNER placeholder that vanishes when the analyst types
    // and is NEVER returned by GetDlgItemTextW), but the bare flag list
    // here reads like real argv at a glance. Other banners self-identify
    // ("Path to ...", "e.g. ...", "AWS, Github, ..."); this one didn't.
    cue(IDC_EDIT_EXTRA_ARGS,        L"Hint: --only-verified  --archive-max-size=50MB  --log-level=-1");
    cue(IDC_EDIT_TAG_THRESHOLD,     L"1 = any hit");
    // Cue width budget: ~91 dlu in IDC_EDIT_SPLIT_ROWS. The "1M" shorthand
    // keeps the full max visible -- the spelled-out "1000000" form sat
    // right at the truncation edge and clipped on tighter font renderings
    // (and was visibly cut off on the older 60-dlu edit).
    cue(IDC_EDIT_SPLIT_ROWS,        L"after 500000 rows");
    if (!s->outputBase.empty())
        cue(IDC_EDIT_OUTPUT_DIR, s->outputBase.c_str());
}

// Set dialog state from Settings on WM_INITDIALOG.
static void PopulateDialog(HWND hDlg, Settings* s, RunCtx* ctx) {
    // Title bar -> append version.
    wchar_t cap[256]; GetWindowTextW(hDlg, cap, _countof(cap));
    std::wstring aug = cap; aug += L"  (v"; aug += VERSION; aug += L")";
    SetWindowTextW(hDlg, aug.c_str());

    // Bold the GROUPBOX titles.
    ApplyGroupTitleFont(hDlg);

    // Tool path + version.
    SetDlgItemTextW(hDlg, IDC_EDIT_TOOL_BIN, s->trufflehogExe.c_str());
    if (s->trufflehogVersion.empty()) {
        SetDlgItemTextW(hDlg, IDC_LABEL_TOOL_VERSION, L"Version: (not detected)");
    } else {
        std::wstring v = L"Version: "; v += s->trufflehogVersion;
        SetDlgItemTextW(hDlg, IDC_LABEL_TOOL_VERSION, v.c_str());
    }

    // Input filters group: items count + size gates + new knobs.
    const wchar_t* modeLabel = (ctx->invocationMode == InvocationMode::Selection)
        ? L"right-click selection"
        : L"Tools \x2192 Run X-Tension";
    // Show the file/directory split so the count reflects what we'll
    // actually scan. X-Ways passes directories through XT_ProcessItem too
    // (they're items in the snapshot), but ShouldScan skips them at scan
    // time. The breakdown matches what the analyst sees in the X-Ways
    // status line ("Selected: N files") instead of an inflated count.
    // Items-to-scan is split into three labels: prefix / count / tail.
    // The COUNT ("N files" or "N") renders bold; prefix stays regular
    // weight. The .rc places each label at a fixed dlu position. Tail is
    // intentionally left blank -- the "(+ N dirs ...; X-Ways filter
    // respected)" parenthetical was redundant noise on the dialog. The
    // invocation mode and filter behavior are reachable via the X-Ways
    // UI / Messages log; the dialog just needs the count.
    // modeLabel kept available for future re-use; suppress unused warning.
    (void)modeLabel;
    const size_t totalItems = ctx->items.size();
    const size_t fileCount  = (totalItems > ctx->dirCount) ? totalItems - ctx->dirCount : totalItems;
    std::wstring countStr = (ctx->dirCount > 0)
        ? FormatW(L"%zu files", fileCount)
        : FormatW(L"%zu", totalItems);
    SetDlgItemTextW(hDlg, IDC_LABEL_SELECTED_COUNT,       L"Items to scan:");
    SetDlgItemTextW(hDlg, IDC_LABEL_SELECTED_COUNT_NUM,   countStr.c_str());
    SetDlgItemTextW(hDlg, IDC_LABEL_SELECTED_COUNT_TAIL,  L"");
    HFONT hBold = EnsureBoldFont(hDlg);
    if (hBold) {
        SendDlgItemMessageW(hDlg, IDC_LABEL_SELECTED_COUNT_NUM,
                            WM_SETFONT, (WPARAM)hBold, TRUE);
    }
    SetDlgItemTextW(hDlg, IDC_EDIT_MIN_SIZE,       FormatW(L"%lld", (long long)s->minSizeBytes).c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_MAX_SIZE,       FormatW(L"%lld", (long long)s->maxSizeMiB).c_str());
    CheckDlgButton(hDlg, IDC_CHK_SKIP_BINARIES,    s->forceSkipBinaries ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemTextW(hDlg, IDC_EDIT_FILTER_ENTROPY, s->filterEntropy.c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_PREFILTER_EXT,  s->prefilterExtensions.c_str());

    // Default = no verification (X-Tension always passes
    // --no-verification). To verify, analyst adds --only-verified to
    // Extra arguments; the cpp detects that override and skips emitting
    // --no-verification.

    SetDlgItemTextW(hDlg, IDC_EDIT_INCLUDE_DETECTORS, s->includeDetectors.c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_EXCLUDE_DETECTORS, s->excludeDetectors.c_str());
    // Concurrency combo: "Auto" + powers of 2 up to host CPU count.
    // Auto = 0 (TruffleHog decides). On cfg restore: snap to the
    // matching item if present, else select Auto. Arbitrary non-power-
    // of-2 cfg values stay in s->concurrency but display as Auto until
    // analyst makes a selection (cfg compat preserved).
    HWND hConc = GetDlgItem(hDlg, IDC_COMBO_CONCURRENCY);
    if (hConc) {
        SendMessageW(hConc, CB_RESETCONTENT, 0, 0);
        SYSTEM_INFO si = {};
        GetSystemInfo(&si);
        DWORD cpuCount = si.dwNumberOfProcessors;
        if (cpuCount < 1) cpuCount = 1;
        int idx = (int)SendMessageW(hConc, CB_ADDSTRING, 0, (LPARAM)L"Auto");
        if (idx >= 0) SendMessageW(hConc, CB_SETITEMDATA, idx, 0);
        // Enumerate every CPU count 1..N. Cap at 128 just in case some
        // future host returns a wild count -- the dropdown would otherwise
        // become unwieldy.
        DWORD limit = (cpuCount > 128) ? 128 : cpuCount;
        for (DWORD p = 1; p <= limit; ++p) {
            wchar_t lab[16];
            swprintf_s(lab, L"%lu", (unsigned long)p);
            int j = (int)SendMessageW(hConc, CB_ADDSTRING, 0, (LPARAM)lab);
            if (j >= 0) SendMessageW(hConc, CB_SETITEMDATA, j, (LPARAM)p);
        }
        int count = (int)SendMessageW(hConc, CB_GETCOUNT, 0, 0);
        int wantSel = 0;
        for (int k = 0; k < count; ++k) {
            if ((int)SendMessageW(hConc, CB_GETITEMDATA, k, 0) == s->concurrency) {
                wantSel = k; break;
            }
        }
        SendMessageW(hConc, CB_SETCURSEL, wantSel, 0);
    }
    SetDlgItemTextW(hDlg, IDC_EDIT_BATCH_SIZE, FormatW(L"%d", s->batchChunkSize).c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_EXTRA_ARGS, s->extraArgs.c_str());

    SetDlgItemTextW(hDlg, IDC_EDIT_OUTPUT_DIR, s->outputBase.c_str());
    CheckDlgButton(hDlg, IDC_CHK_KEEP_EXTRACTED,    s->keepExtracted    ? BST_CHECKED : BST_UNCHECKED);
    // "Add findings" tri-state: derive from the two cfg fields. The
    // unusual (addToReportTable=false, addComment=true) combination
    // isn't directly representable by the tri-state; treat it as fully
    // CHECKED (preserve the comments intent + also turn on Report Table
    // since the unified control couples them).
    UINT addTri = BST_UNCHECKED;
    if (s->addToReportTable && s->addComment) addTri = BST_CHECKED;
    else if (s->addToReportTable)              addTri = BST_INDETERMINATE;
    else if (s->addComment)                    addTri = BST_CHECKED;     // unusual combo -> "both on"
    CheckDlgButton(hDlg, IDC_CHK_ADD_REPORT_TABLE,  addTri);
    SetDlgItemTextW(hDlg, IDC_EDIT_TAG_THRESHOLD,   FormatW(L"%d", s->tagThreshold).c_str());
    CheckDlgButton(hDlg, IDC_CHK_VERBOSE,           s->verbose          ? BST_CHECKED : BST_UNCHECKED);
    // Tri-state findings TSV. Map enum -> Win32 check state.
    UINT triState = (s->findingsOutput == FindingsOutputMode::Full)     ? BST_CHECKED
                  : (s->findingsOutput == FindingsOutputMode::Redacted) ? BST_INDETERMINATE
                                                                         : BST_UNCHECKED;
    CheckDlgButton(hDlg, IDC_CHK_FINDINGS_TSV,      triState);
    // Split-rows input: leave blank when the analyst hasn't customised so the
    // cue banner ("500000") shows; populate only when the cfg value differs
    // from the default so power users see their override.
    if (s->findingsRowsPerSheet != 500000)
        SetDlgItemTextW(hDlg, IDC_EDIT_SPLIT_ROWS, FormatW(L"%d", s->findingsRowsPerSheet).c_str());

    // Cue-banner hints (placeholder text shown when the edit is empty).
    ApplyCueBanners(hDlg, s);

    // Progress row: always visible. Idle state pre-Run (bar at 0); the
    // worker tickles it once Run is clicked.
    HWND hProg = GetDlgItem(hDlg, IDC_PROGRESS_RUN);
    SendMessageW(hProg, PBM_SETRANGE32, 0, 1000);
    SendMessageW(hProg, PBM_SETPOS, 0, 0);
    SetDlgItemTextW(hDlg, IDC_LABEL_PROGRESS_STATUS, L"Ready.");
}

// =============================================================================
//  Tooltip popups for non-obvious controls
// =============================================================================
//   Win32 TOOLTIPS_CLASS attached via TTF_SUBCLASS — the tooltip control hooks
//   each target's mouse events itself, no per-message forwarding needed. Lives
//   for the dialog lifetime; destroyed in WM_DESTROY.
//
//   Skips self-evident controls (path edits, Browse buttons, action buttons,
//   the items-count label) to keep the dialog free of patronizing chatter.
struct TipDef { int id; const wchar_t* text; };

static const TipDef kTooltips[] = {
    { IDC_EDIT_MIN_SIZE,
      L"Items smaller than this (in bytes) are skipped before extraction.\r\n"
      L"Default 1 = skip zero-byte items only." },

    { IDC_EDIT_MAX_SIZE,
      L"Items larger than this (in MiB) are skipped before extraction.\r\n\r\n"
      L"TruffleHog can scan huge files, but the per-item invocation cost "
      L"rarely pays off on multi-GB items that are unlikely to contain "
      L"text-shaped secrets." },

    { IDC_CHK_SKIP_BINARIES,
      L"--force-skip-binaries\r\n\r\n"
      L"TruffleHog skips executables and binary blobs entirely (PE / ELF / "
      L"Mach-O). This is the single biggest false-positive killer on a "
      L"typical Windows-image triage where compiled artifacts dominate.\r\n\r\n"
      L"Leave OFF only when hunting for embedded secrets inside compiled code." },

    { IDC_EDIT_FILTER_ENTROPY,
      L"--filter-entropy=N\r\n\r\n"
      L"Shannon-entropy threshold. Drops unverified hits whose Raw value "
      L"falls below this entropy as likely false positives.\r\n\r\n"
      L"Typical starting point: 3.0. Higher = stricter (fewer hits).\r\n"
      L"Only effective with --no-verification (the default).\r\n"
      L"Leave blank to disable." },

    { IDC_EDIT_PREFILTER_EXT,
      L"Comma-separated file extensions to SKIP before extraction.\r\n\r\n"
      L"Applied BY THE X-TENSION before we hand bytes to TruffleHog, so it "
      L"saves the per-item extract cost too. Distinct from "
      L"--force-skip-binaries which TruffleHog applies AFTER reading the "
      L"file.\r\n\r\n"
      L"Default list: media (jpg/png/mp4/...), compiled artifacts "
      L"(exe/dll/obj/...), and archive containers (zip/7z/gz/...).\r\n\r\n"
      L"No dot, lowercase. Extension match is case-insensitive." },

    { IDC_RADIO_VERIFY_NONE,
      L"--no-verification (default for forensic workstations)\r\n\r\n"
      L"TruffleHog will NOT reach out to provider APIs (AWS STS, GitHub, "
      L"Slack, Stripe, ...). Correct for air-gapped triage boxes and any "
      L"workstation where outbound traffic is policy-restricted." },

    { IDC_RADIO_VERIFY_ALL,
      L"No verification flag — full verification path\r\n\r\n"
      L"TruffleHog validates each candidate against the real provider API. "
      L"Generates outbound traffic AND may trigger account-protection signals "
      L"on the target accounts (especially AWS/GCP/Azure).\r\n\r\n"
      L"Use ONLY on a permitted, isolated triage box with the analyst's "
      L"informed consent." },

    { IDC_RADIO_VERIFY_ONLY,
      L"--only-verified\r\n\r\n"
      L"Same outbound traffic and risk as 'Verify and report all', but emits "
      L"ONLY findings that pass live verification. Network access to the "
      L"target providers is required." },

    { IDC_EDIT_INCLUDE_DETECTORS,
      L"--include-detectors=<csv>\r\n\r\n"
      L"Comma-separated detector names (TruffleHog Protobuf names) or "
      L"numeric IDs. Empty = all detectors.\r\n\r\n"
      L"Examples:  AWS, Github, Slack, Stripe, GCP, Postman" },

    { IDC_EDIT_EXCLUDE_DETECTORS,
      L"--exclude-detectors=<csv>\r\n\r\n"
      L"Comma-separated detector names or IDs to suppress. Takes precedence "
      L"over the include list above. Useful for silencing a particular noisy "
      L"detector class on a case-by-case basis." },

    { IDC_COMBO_CONCURRENCY,
      L"--concurrency=N\r\n\r\n"
      L"TruffleHog's internal worker count per batch invocation. Dropdown "
      L"is populated with 'Auto' + powers of 2 up to the host CPU count.\r\n\r\n"
      L"  Auto - let TruffleHog decide (defaults to host CPU count). DEFAULT.\r\n"
      L"  1..N - cap worker count to a specific number\r\n\r\n"
      L"Lower the value when many concurrent items are saturating the host "
      L"(noisy stderr, slow item-extraction, swapping)." },

    { IDC_EDIT_BATCH_SIZE,
      L"Items per TruffleHog invocation (X-Tension-side batching).\r\n\r\n"
      L"Default 100. Range from this dialog: 10 .. 5000. The cfg can push "
      L"to 20000 for experimental large-batch runs (key: batch_chunk_size). "
      L"A cfg value of 0 means 'scan everything in one batch'.\r\n\r\n"
      L"Larger = faster (TruffleHog's ~2.5s startup amortises across more "
      L"items) but more peak disk and slower Cancel response (Cancel only "
      L"fires between batches). Smaller = lower memory + faster Cancel.\r\n\r\n"
      L"TruffleHog has no documented hard limit on input file count, but "
      L"findings accumulate in RAM during a run -- huge batches on a "
      L"findings-heavy case can balloon memory." },

    { IDC_EDIT_EXTRA_ARGS,
      L"Free-form pass-through to the TruffleHog command line. Spliced "
      L"after the built-in flags.\r\n\r\n"
      L"VERIFY FINDINGS IS DISABLED BY DEFAULT. The X-Tension passes "
      L"--no-verification to keep IOCs off the wire. To opt INTO live "
      L"verification (queries AWS STS / GitHub / Slack / etc), add:\r\n"
      L"  --only-verified\r\n"
      L"to Extra arguments -- the X-Tension detects it and skips its own "
      L"--no-verification so the two flags don't conflict.\r\n\r\n"
      L"Other useful additions:\r\n"
      L"  --log-level=-1   (silence trufflehog stderr)\r\n"
      L"  --log-level=2    (verbose-info-2: startup banner, worker counts)\r\n"
      L"  --archive-max-depth=2 --archive-max-size=50MB\r\n"
      L"  --archive-timeout=60s\r\n"
      L"  --detector-timeout=30s\r\n"
      L"  --print-avg-detector-time\r\n"
      L"  --max-decode-depth=5\r\n\r\n"
      L"TruffleHog's --log-level is a verbose-info COUNTER, not stdlib "
      L"levels: -1 silent, 0..5 progressively more verbose info-N tiers." },

    { IDC_EDIT_OUTPUT_DIR,
      L"Base directory for the run. Each scan lands in:\r\n"
      L"  <output>\\xways-trufflehog\\run-YYYYMMDD-HHMMSS\\\r\n\r\n"
      L"Defaults to the X-Ways evidence working directory (General Options "
      L"-> Folders -> Internally used directory)." },

    { IDC_CHK_KEEP_EXTRACTED,
      L"Keep the per-item extracted bytes under run\\in\\ after each scan.\r\n\r\n"
      L"Useful for re-running TruffleHog manually on the same bytes, or "
      L"verifying exactly what was scanned. Turn OFF to save disk on large "
      L"runs (the .jsonl output is what carries the findings forward anyway)." },

    { IDC_CHK_ADD_REPORT_TABLE,
      L"Combined Add-findings control. Cycles through three states "
      L"(click: unchecked -> checked -> indeterminate, Win32 default):\r\n\r\n"
      L"  [ ] unchecked     - DO NOT tag findings\r\n"
      L"  [-] indeterminate - PER-DETECTOR Report Tables only\r\n"
      L"                       trufflehog: AWS / GitHub / Slack / ...\r\n"
      L"  [v] checked       - Report Tables + Comments-column summary\r\n"
      L"                       (DEFAULT)\r\n\r\n"
      L"Comments column summary looks like:\r\n"
      L"  [xways-trufflehog] 3 finding(s), 1 verified, first @ line 42\r\n"
      L"     \x2014 AWS, Slack @ Users\\bob\\.aws\\credentials" },

    { IDC_EDIT_TAG_THRESHOLD,
      L"Minimum number of findings on a single item before that item gets "
      L"tagged.\r\n\r\n"
      L"1 = tag any hit (default).\r\n"
      L"Raise to suppress items with many low-quality detector matches but "
      L"no individually-strong signal." },

    { IDC_CHK_VERBOSE,
      L"Print per-item finding lines to the X-Ways Messages window.\r\n\r\n"
      L"Distinct from TruffleHog's own --log-level (pass via Extra args "
      L"if you want to control that). This toggles only the X-Tension's "
      L"own LogVerbose() output:\r\n\r\n"
      L"  ON  = one line per item that produced a finding\r\n"
      L"  OFF = only the run-start banner and the final summary" },

    { IDC_CHK_FINDINGS_TSV,
      L"Export findings to a consolidated spreadsheet at end of run, named "
      L"<evidence>-trufflehog.xlsx (Office Open XML, opens in Excel / "
      L"LibreOffice / Google Sheets). Frozen header row + autoFilter.\r\n\r\n"
      L"Click cycles through three states:\r\n"
      L"  [ ] unchecked     - no file written\r\n"
      L"  [-] indeterminate - file written WITH partial redaction of Raw\r\n"
      L"  [v] checked       - file written with the FULL raw secret values\r\n\r\n"
      L"Same exposure as the per-chunk .jsonl files in run\\out\\ -- this "
      L"is the consolidated/analyst-friendly form. Redact when shipping a "
      L"case folder to someone who shouldn't see live secrets." },


    { IDC_EDIT_SPLIT_ROWS,
      L"Split the findings XLSX into multiple files when the per-file row "
      L"count exceeds this value. Keeps each spreadsheet snappy in Excel "
      L"on high-false-positive runs.\r\n\r\n"
      L"Default: 500,000 rows per file.\r\n"
      L"Hard cap: 1,000,000 rows per file (Excel's per-sheet limit is "
      L"1,048,576). Leave the field blank for the default.\r\n\r\n"
      L"When the run produces more rows than the cap, files get a numeric "
      L"suffix:\r\n"
      L"  <evidence>-trufflehog-1.xlsx\r\n"
      L"  <evidence>-trufflehog-2.xlsx\r\n"
      L"  ...\r\n"
      L"Single-file runs keep the un-suffixed name." },

    { IDC_BTN_RUN,
      L"Run the scan with the current dialog settings.\r\n\r\n"
      L"Disabled until the trufflehog.exe path has been validated -- the "
      L"X-Tension runs `<exe> --version` asynchronously and only enables "
      L"Run when the output identifies the binary as TruffleHog. If the "
      L"button stays disabled, check the Version: line at the top of the "
      L"dialog for the reason.\r\n\r\n"
      L"Every click also saves the current settings to xways-trufflehog.cfg "
      L"(the previous cfg is backed up to .cfg.bak).\r\n\r\n"
      L"Hold Ctrl while clicking to SAVE the cfg WITHOUT starting the scan "
      L"-- useful for tuning defaults you want to keep across runs. While "
      L"Ctrl is held, the button label flips to 'Save' and turns blue." },

    { IDCANCEL,
      L"Close: close the dialog (or, during a scan, stop the worker).\r\n\r\n"
      L"Hold Ctrl to turn this into 'Save as...' -- click while Ctrl "
      L"is held to open a file picker and save the current settings to a "
      L"chosen .cfg path. Useful for snapshotting a working configuration "
      L"before experimenting, or for shipping a cfg to another analyst's "
      L"machine.\r\n\r\n"
      L"Save-as also closes the dialog. Use Ctrl+Run instead if you want "
      L"to save to the standard sidecar without closing.\r\n\r\n"
      L"The Ctrl-mode only kicks in when no scan is running; during an "
      L"active scan, the button stays its normal Close/Cancel-the-worker self." },
};

static HWND CreateAndAttachTooltips(HWND hDlg) {
    HWND hTip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr,
                                WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                hDlg, nullptr, g_hSelf, nullptr);
    if (!hTip) return nullptr;
    // Wrap multi-line tips at ~360 px. Default would render one giant line.
    SendMessageW(hTip, TTM_SETMAXTIPWIDTH, 0, 360);
    // Auto-pop = 60 s (default is 5 s, which is too short for the multi-
    // line tooltips). The tip dismisses as soon as the mouse moves off
    // the field, so the long timeout is only spent if the analyst is
    // actively reading.
    SendMessageW(hTip, TTM_SETDELAYTIME, TTDT_AUTOPOP, MAKELPARAM(60000, 0));
    for (const auto& t : kTooltips) {
        HWND hCtl = GetDlgItem(hDlg, t.id);
        if (!hCtl) continue;
        TOOLINFOW ti = {};
        ti.cbSize   = sizeof(ti);
        ti.uFlags   = TTF_IDISHWND | TTF_SUBCLASS;
        ti.hwnd     = hDlg;
        ti.uId      = (UINT_PTR)hCtl;
        ti.lpszText = (LPWSTR)t.text;
        SendMessageW(hTip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
    }
    return hTip;
}

// Forward declaration.
static INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp);

// Subclass for the IDC_PROGRESS_RUN control. Lets us paint "Completed" in
// bold white over the filled bar once a scan finishes. The default
// msctls_progress32 doesn't support owner-draw, so we subclass instead and
// draw on top of the bar's own paint output. dwRefData == 0 -> normal bar;
// dwRefData == 1 -> overlay enabled. Toggled via SetWindowSubclass from
// WM_APP_DONE (on) and the Run-click handler (off, for the next run).
static LRESULT CALLBACK ProgressOverlayProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp,
                                            UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    if (msg == WM_NCDESTROY) {
        RemoveWindowSubclass(hWnd, ProgressOverlayProc, uIdSubclass);
        return DefSubclassProc(hWnd, msg, wp, lp);
    }
    if (msg == WM_PAINT && dwRefData) {
        // Let the comctl progress class paint itself (validates the update
        // region via BeginPaint/EndPaint), then overlay our text using a
        // freshly-acquired client DC.
        LRESULT r = DefSubclassProc(hWnd, msg, wp, lp);
        HDC hDC = GetDC(hWnd);
        if (hDC) {
            RECT rc; GetClientRect(hWnd, &rc);
            LOGFONTW lf = {};
            lf.lfHeight = -MulDiv(11, GetDeviceCaps(hDC, LOGPIXELSY), 72);
            lf.lfWeight = FW_BOLD;
            wcscpy_s(lf.lfFaceName, L"Segoe UI");
            HFONT hFont = CreateFontIndirectW(&lf);
            HFONT old   = hFont ? (HFONT)SelectObject(hDC, hFont) : nullptr;
            SetBkMode(hDC, TRANSPARENT);
            SetTextColor(hDC, RGB(255, 255, 255));
            DrawTextW(hDC, L"Completed", -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            if (old) SelectObject(hDC, old);
            if (hFont) DeleteObject(hFont);
            ReleaseDC(hWnd, hDC);
        }
        return r;
    }
    return DefSubclassProc(hWnd, msg, wp, lp);
}

static INT_PTR CALLBACK SettingsDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp) {
    static Settings* s = nullptr;
    static RunCtx*   ctx = nullptr;
    static HWND      s_hTooltip = nullptr;
    // Ctrl-to-save: a low-frequency timer polls VK_CONTROL and flips the Run
    // button label between "&Run" and "&Save" when our dialog has focus.
    // g_runCtrlDown tracks the current displayed label state for the Run
    // button; g_closeCtrlDown tracks the Close/Cancel button (which becomes
    // "Save as..." in Ctrl mode, ONLY when no worker is running).
    // We only call SetDlgItemTextW on transitions (no flicker).
    static bool      g_runCtrlDown = false;
    static bool      g_closeCtrlDown = false;
    constexpr UINT_PTR kCtrlPollTimerId = 0xAB10;
    constexpr UINT    kCtrlPollMs   = 100;
    // Open-output-folder flash on scan completion. Ticks count down at
    // kFlashPeriodMs intervals; odd values render the button green.
    static int        s_openOutputFlashTicks = 0;
    constexpr UINT_PTR kFlashTimerId = 0xC002;
    constexpr UINT    kFlashPeriodMs = 180;
    constexpr UINT_PTR kProgressSubclassId = 0xC003;

    switch (msg) {
    case WM_INITDIALOG: {
        // Standalone mode passes a std::pair<Settings*, RunCtx*>* via lParam.
        // Managed mode (xways-xt-manager host) creates the embedded dialog
        // with lParam=0 — fall back to the module-local managed objects so the
        // dialog populates from cfg defaults and TrufflehogHarvestSettings has
        // somewhere to read controls back into. Mirrors hindsight's
        // g_managed_state / ual-timeliner's g_managed_dlg_state fallback.
        if (lp) {
            auto* pair = reinterpret_cast<std::pair<Settings*, RunCtx*>*>(lp);
            s   = pair->first;
            ctx = pair->second;
        } else {
            s   = &g_managed_settings;
            ctx = &g_managed_runctx;
        }
        ApplyTitleIcon(hDlg);
        PopulateDialog(hDlg, s, ctx);
        // Version label starts as "(detecting...)" and updates via
        // WM_APP_VERSION when the async probe completes. PopulateDialog above
        // wrote "(not detected)" because s->trufflehogVersion was empty --
        // overwrite it now that we're about to fire the probe. The Run
        // button is force-disabled until the probe confirms the exe really
        // is TruffleHog (g_exeValid flips in WM_APP_VERSION). Reset any
        // stale rejection state from a previous dialog instance -- statics
        // survive across dialog opens within the same DLL load. Explicit
        // KillTimer on the helper-flash id is symmetry-with-WM_DESTROY
        // belt-and-braces -- a clean WM_DESTROY would have already done it,
        // but if the prior tear-down was abnormal there could be a stale
        // timer hanging around.
        KillTimer(hDlg, kHelperFlashTimerId);
        g_exeValid         = false;
        g_helperRejected   = false;
        g_helperFlashTicks = 0;
        EnableWindow(GetDlgItem(hDlg, IDC_BTN_RUN), FALSE);
        if (s && !s->trufflehogExe.empty()) {
            SetDlgItemTextW(hDlg, IDC_LABEL_TOOL_VERSION, L"Version: (detecting...)");
            StartAsyncVersionProbe(hDlg, s->trufflehogExe);
        }
        s_hTooltip = CreateAndAttachTooltips(hDlg);
        g_runCtrlDown   = false;
        g_closeCtrlDown = false;
        // Ctrl-to-save: DM_SETDEFID so Enter still triggers Run even with
        // BS_OWNERDRAW (which suppresses the DEFPUSHBUTTON default-button
        // ring). Initialise button labels explicitly.
        SendMessageW(hDlg, DM_SETDEFID, IDC_BTN_RUN, 0);
        SetDlgItemTextW(hDlg, IDC_BTN_RUN, L"Run");
        SetDlgItemTextW(hDlg, IDCANCEL, L"Close");
        // Owner-draw every action button in the bottom row so they all
        // render with the same grey skin. Without this, About / Open cfg
        // pick up the system default-theme (white) while the rest are
        // owner-drawn -- visually inconsistent.
        // - Run: also paints blue when Ctrl held ("Save" mode).
        // - Cancel: paints blue when Ctrl held ("Save as..." mode),
        //   only when no worker is running.
        // - Open output folder: flashes green for a moment after a successful
        //   scan completes (WM_APP_DONE wp==1 starts the flash timer).
        // - About / Open cfg: plain owner-drawn buttons (cosmetic only).
        for (int id : { IDC_BTN_RUN, (int)IDCANCEL, IDC_BTN_OPEN_OUTPUT,
                        IDC_BTN_ABOUT, IDC_BTN_OPEN_CFG }) {
            HWND h = GetDlgItem(hDlg, id);
            if (h) {
                LONG_PTR style = GetWindowLongPtrW(h, GWL_STYLE);
                SetWindowLongPtrW(h, GWL_STYLE, style | BS_OWNERDRAW);
            }
        }
        // Subclass the progress bar so we can overlay "Completed" text on it
        // once a run finishes (toggled via SetWindowSubclass refdata).
        HWND hProgInit = GetDlgItem(hDlg, IDC_PROGRESS_RUN);
        if (hProgInit) SetWindowSubclass(hProgInit, ProgressOverlayProc,
                                         kProgressSubclassId, 0);
        s_openOutputFlashTicks = 0;
        SetTimer(hDlg, kCtrlPollTimerId, kCtrlPollMs, nullptr);
        SetFocus(GetDlgItem(hDlg, IDC_BTN_RUN));
        return FALSE;
    }

    case WM_DESTROY: {
        KillTimer(hDlg, kCtrlPollTimerId);
        KillTimer(hDlg, kFlashTimerId);
        KillTimer(hDlg, kHelperFlashTimerId);
        // Drain any queued WM_APP_* messages whose payloads we own on the
        // heap. Without this sweep, Windows discards posted messages for a
        // destroyed window and the payloads are orphaned. Two message types
        // carry heap payloads and need draining (with different allocators):
        //   WM_APP_STATUS  -- malloc'd wchar_t* from PostStatus (free)
        //   WM_APP_VERSION -- new'd VersionProbeResult* from worker (delete)
        // WM_APP_PROGRESS / WM_APP_DONE / WM_APP_MARQUEE carry only wparam
        // flags, no payload. Bumping g_probeToken first so any probe that
        // completes AFTER us also frees its own result (PostMessage fails
        // because hDlg is gone -> the worker's failure branch deletes it).
        ++g_probeToken;
        MSG drainMsg;
        while (PeekMessageW(&drainMsg, hDlg, WM_APP_STATUS, WM_APP_STATUS, PM_REMOVE)) {
            if (drainMsg.lParam) free(reinterpret_cast<wchar_t*>(drainMsg.lParam));
        }
        while (PeekMessageW(&drainMsg, hDlg, WM_APP_VERSION, WM_APP_VERSION, PM_REMOVE)) {
            if (drainMsg.lParam)
                delete reinterpret_cast<VersionProbeResult*>(drainMsg.lParam);
        }
        if (s_hTooltip) { DestroyWindow(s_hTooltip); s_hTooltip = nullptr; }
        return FALSE;
    }

    case WM_CTLCOLORSTATIC: {
        // Recolour ONLY the Version readout when a helper-exe rejection is
        // active. Bright red (220,0,0) on even tick counts (or once the
        // flash has settled, ticks==0), dark red (140,0,0) on odd ticks
        // -- gives the 250 ms flash effect. All other statics fall through
        // to default handling so nothing else gets coloured.
        if (g_helperRejected) {
            HWND hCtl = (HWND)lp;
            if (hCtl && hCtl == GetDlgItem(hDlg, IDC_LABEL_TOOL_VERSION)) {
                HDC hdc = (HDC)wp;
                bool brightPhase = (g_helperFlashTicks == 0) ||
                                   ((g_helperFlashTicks & 1) == 0);
                SetTextColor(hdc, brightPhase ? RGB(220, 0, 0) : RGB(140, 0, 0));
                SetBkMode(hdc, TRANSPARENT);
                return (INT_PTR)GetSysColorBrush(COLOR_BTNFACE);
            }
        }
        break;  // default handling for all other statics
    }

    case WM_TIMER:
        if (wp == kHelperFlashTimerId) {
            // Decrement and invalidate; WM_CTLCOLORSTATIC reads
            // g_helperFlashTicks to pick the colour shade. At zero we stop
            // the timer -- the label stays solid bright red.
            if (!g_helperRejected) {
                KillTimer(hDlg, kHelperFlashTimerId);
                return TRUE;
            }
            if (g_helperFlashTicks > 0) {
                --g_helperFlashTicks;
                HWND hVer = GetDlgItem(hDlg, IDC_LABEL_TOOL_VERSION);
                if (hVer) InvalidateRect(hVer, nullptr, TRUE);
                if (g_helperFlashTicks == 0)
                    KillTimer(hDlg, kHelperFlashTimerId);
            }
            return TRUE;
        }
        if (wp == kFlashTimerId) {
            if (s_openOutputFlashTicks > 0) {
                --s_openOutputFlashTicks;
                InvalidateRect(GetDlgItem(hDlg, IDC_BTN_OPEN_OUTPUT), nullptr, TRUE);
                if (s_openOutputFlashTicks == 0) {
                    KillTimer(hDlg, kFlashTimerId);
                }
            } else {
                KillTimer(hDlg, kFlashTimerId);
            }
            return TRUE;
        }
        if (wp == kCtrlPollTimerId) {
            bool ctrlDown = (GetKeyState(VK_CONTROL) & 0x8000) != 0;

            // Run button: flips on Ctrl regardless of worker state (the
            // click handler is the source of truth and disables save during
            // an in-progress scan via the busy-state gate).
            if (ctrlDown != g_runCtrlDown) {
                g_runCtrlDown = ctrlDown;
                SetDlgItemTextW(hDlg, IDC_BTN_RUN, ctrlDown ? L"Save" : L"Run");
                InvalidateRect(GetDlgItem(hDlg, IDC_BTN_RUN), nullptr, TRUE);
            }

            // Close/Cancel button: only flips to "Save as..." when Ctrl is
            // held AND no worker is running. During a scan, Close stays
            // "Close" / acts as Cancel so Ctrl never creates a
            // confusing "Cancel-or-save?" affordance mid-run.
            bool closeSaveMode = ctrlDown && (g_workerThread == nullptr);
            if (closeSaveMode != g_closeCtrlDown) {
                g_closeCtrlDown = closeSaveMode;
                SetDlgItemTextW(hDlg, IDCANCEL,
                                closeSaveMode ? L"Save as..." : L"Close");
                InvalidateRect(GetDlgItem(hDlg, IDCANCEL), nullptr, TRUE);
            }
            return TRUE;
        }
        break;

    case WM_DRAWITEM: {
        // Owner-draw for the Run/Save AND Cancel/SaveAs buttons. In their
        // default state we draw the standard themed look; when Ctrl makes
        // the button an "alternate action" (Save / Save as...) we
        // paint the face in the Windows accent blue with white text so
        // the analyst sees clearly that clicking does something different
        // than the un-modified action.
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lp;
        const bool isRunBtn        = (dis->CtlID == IDC_BTN_RUN);
        const bool isCancelBtn     = (dis->CtlID == IDCANCEL);
        const bool isOpenOutputBtn = (dis->CtlID == IDC_BTN_OPEN_OUTPUT);
        const bool isAboutBtn      = (dis->CtlID == IDC_BTN_ABOUT);
        const bool isOpenCfgBtn    = (dis->CtlID == IDC_BTN_OPEN_CFG);
        // About / Open cfg are owner-drawn purely to keep the bottom-row
        // buttons visually consistent (otherwise theming makes them
        // stand out white against the grey owner-drawn neighbours).
        // They never enter alt/flash modes -- always plain grey.
        if (!isRunBtn && !isCancelBtn && !isOpenOutputBtn &&
            !isAboutBtn && !isOpenCfgBtn) break;

        // "Alternate mode" for Run/Cancel = blue Ctrl-paint. For Open output
        // = green flash phase (odd tick counts render green).
        bool altMode = (isRunBtn && g_runCtrlDown) ||
                       (isCancelBtn && g_closeCtrlDown);
        bool flashOn = isOpenOutputBtn && (s_openOutputFlashTicks > 0) &&
                       ((s_openOutputFlashTicks & 1) != 0);
        const bool isPressed = (dis->itemState & ODS_SELECTED) != 0;
        const bool isFocus   = (dis->itemState & ODS_FOCUS)    != 0;
        const bool isDisabled= (dis->itemState & ODS_DISABLED) != 0;
        // Alias for legibility inside the existing color math below.
        const bool isSave    = altMode;

        // Accent blue ~ matches Win10/11 default checkbox-checked color.
        // Slightly darker when pressed for affordance. Flash green wins
        // when active (only ever set on IDC_BTN_OPEN_OUTPUT).
        COLORREF bg = flashOn ? (isPressed ? RGB(20, 120, 45) : RGB(30, 160, 60))
                  : isSave    ? (isPressed ? RGB(0, 90, 168)  : RGB(0, 120, 215))
                              : GetSysColor(COLOR_BTNFACE);
        COLORREF fg = (flashOn || isSave) ? RGB(255, 255, 255)
                             : (isDisabled ? GetSysColor(COLOR_GRAYTEXT)
                                           : GetSysColor(COLOR_BTNTEXT));

        // Fill background.
        HBRUSH hbr = CreateSolidBrush(bg);
        FillRect(dis->hDC, &dis->rcItem, hbr);
        DeleteObject(hbr);

        // 1-pixel frame so the button has visible edges even on light
        // themes where the accent color would otherwise blend with surroundings.
        HBRUSH frameBr = CreateSolidBrush(flashOn ? RGB(20, 100, 35)
                                       :  isSave  ? RGB(0, 70, 140)
                                                  : GetSysColor(COLOR_3DSHADOW));
        FrameRect(dis->hDC, &dis->rcItem, frameBr);
        DeleteObject(frameBr);

        // Focus rect (inset by 3 px) when keyboard-focused.
        if (isFocus) {
            RECT focus = dis->rcItem;
            InflateRect(&focus, -3, -3);
            DrawFocusRect(dis->hDC, &focus);
        }

        // Text. Use the dialog's current font so weights match other buttons.
        wchar_t txt[64] = {0};
        GetWindowTextW(dis->hwndItem, txt, _countof(txt));
        HFONT hFont = (HFONT)SendMessageW(dis->hwndItem, WM_GETFONT, 0, 0);
        HFONT old = hFont ? (HFONT)SelectObject(dis->hDC, hFont) : nullptr;
        SetBkMode(dis->hDC, TRANSPARENT);
        SetTextColor(dis->hDC, fg);
        DrawTextW(dis->hDC, txt, -1, &dis->rcItem,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        if (old) SelectObject(dis->hDC, old);
        return TRUE;
    }

    case WM_COMMAND: {
        const WORD id = LOWORD(wp);
        if (id == IDC_BTN_BROWSE_TOOL) {
            wchar_t cur[MAX_PATH] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_TOOL_BIN, cur, MAX_PATH);
            std::wstring picked = BrowseForFile(hDlg, cur);
            if (!picked.empty()) {
                SetDlgItemTextW(hDlg, IDC_EDIT_TOOL_BIN, picked.c_str());
                if (s) {
                    s->trufflehogExe = picked;
                    s->trufflehogVersion.clear();  // overwritten by WM_APP_VERSION
                }
                // Reset validity until the new probe confirms it. Even if
                // the old exe was valid, this new file is unknown until the
                // identity check (PE VERSIONINFO + --version banner) passes.
                // Clear any prior rejection state first so the bold-red flash
                // doesn't bleed into the new validation run.
                ClearHelperRejection(hDlg);
                g_exeValid = false;
                EnableWindow(GetDlgItem(hDlg, IDC_BTN_RUN), FALSE);
                SetDlgItemTextW(hDlg, IDC_LABEL_TOOL_VERSION, L"Version: (detecting...)");
                StartAsyncVersionProbe(hDlg, picked);
            }
            return TRUE;
        }
        if (id == IDC_BTN_BROWSE_OUTPUT) {
            wchar_t cur[MAX_PATH] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_OUTPUT_DIR, cur, MAX_PATH);
            std::wstring picked = BrowseForFolder(hDlg, cur, L"Select output directory");
            if (!picked.empty()) SetDlgItemTextW(hDlg, IDC_EDIT_OUTPUT_DIR, picked.c_str());
            return TRUE;
        }
        if (id == IDC_BTN_ABOUT) {
            DialogBoxParamW(g_hSelf, MAKEINTRESOURCEW(IDD_ABOUT),
                            hDlg, AboutDlgProc, 0);
            return TRUE;
        }
        if (id == IDC_BTN_OPEN_OUTPUT) {
            std::wstring target = g_lastRunDir;
            if (target.empty()) {
                wchar_t buf[MAX_PATH] = {0};
                GetDlgItemTextW(hDlg, IDC_EDIT_OUTPUT_DIR, buf, MAX_PATH);
                target = buf;
            }
            if (!target.empty() && DirExists(target))
                ShellExecuteW(hDlg, L"open", target.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            else
                MessageBoxW(hDlg, L"No output folder yet — run a scan first, or set the output directory.",
                            NAME, MB_OK | MB_ICONINFORMATION);
            return TRUE;
        }
        if (id == IDC_BTN_OPEN_CFG) {
            // Open xways-trufflehog.cfg in the OS default text editor.
            // Create it from .example or embedded defaults if absent so the
            // button never opens "nothing".
            std::wstring cfgPath = GetSelfDirectory() + L"\\xways-trufflehog.cfg";
            EnsureCfgExists(cfgPath);
            if (FileExists(cfgPath)) {
                ShellExecuteW(hDlg, L"open", cfgPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            } else {
                MessageBoxW(hDlg, L"Could not locate or create xways-trufflehog.cfg next to the DLL.",
                            NAME, MB_OK | MB_ICONWARNING);
            }
            return TRUE;
        }
        if (id == IDC_BTN_RUN) {
            if (g_workerThread) return TRUE;  // already running
            if (!s || !ctx) return TRUE;
            if (!ReadDialogToSettings(hDlg, *s)) return TRUE;

            // Save the dialog state to the cfg every click (Run AND
            // Ctrl+Run). Keeps the cfg in sync with what the analyst
            // last did. SaveSettingsToCfg rotates the previous cfg to
            // <path>.bak so destructive overwrite is recoverable.
            // EXCEPT: refuse to save when helper-exe is in the rejected
            // state -- ShowHelperRejection echoed the rejected path back
            // into IDC_EDIT_TOOL_BIN (intentional: analyst sees what got
            // rejected), and persisting THAT path to cfg would poison
            // every subsequent dialog open. Run is already disabled when
            // rejected, so reaching this branch via the standard Run gate
            // shouldn't happen, but Ctrl+Run is allowed even with Run
            // visually labelled "Save", so the guard is load-bearing.
            if (g_helperRejected) {
                Log(L"skipping cfg-save: helper-exe rejected -- pick a valid trufflehog.exe via Browse before saving");
            } else {
                std::wstring cfgPath = GetSelfDirectory() + L"\\xways-trufflehog.cfg";
                if (SaveSettingsToCfg(cfgPath, *s)) {
                    LogVerbose(L"saved cfg: " + cfgPath);
                } else {
                    Log(L"warning: could not save cfg to " + cfgPath);
                }
            }

            // Ctrl held at click time = "save only, don't run". Check
            // GetKeyState NOT the cached timer state -- the timer
            // is a UI-label hint; this read is the source of truth.
            bool ctrlHeld = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
            if (ctrlHeld) {
                SetDlgItemTextW(hDlg, IDC_LABEL_PROGRESS_STATUS,
                                L"Settings saved to cfg. (Ctrl+Run: scan NOT started.)");
                return TRUE;
            }

            // Clear any "Completed" overlay + flash left over from a previous
            // run before starting the new one.
            s_openOutputFlashTicks = 0;
            KillTimer(hDlg, kFlashTimerId);
            HWND hProgClear = GetDlgItem(hDlg, IDC_PROGRESS_RUN);
            if (hProgClear) {
                SetWindowSubclass(hProgClear, ProgressOverlayProc,
                                  kProgressSubclassId, /*refdata*/0);
                InvalidateRect(hProgClear, nullptr, TRUE);
            }
            InvalidateRect(GetDlgItem(hDlg, IDC_BTN_OPEN_OUTPUT), nullptr, TRUE);

            // Spawn worker.
            g_worker = new WorkerCtx{};
            g_worker->s    = s;
            g_worker->ctx  = ctx;
            g_worker->hDlg = hDlg;
            SetDialogBusy(hDlg, true);
            SetDlgItemTextW(hDlg, IDC_LABEL_PROGRESS_STATUS, L"Starting...");
            g_workerThread = (HANDLE)_beginthreadex(nullptr, 0, WorkerThread, g_worker, 0, nullptr);
            if (!g_workerThread) {
                MessageBoxW(hDlg, L"Failed to start the scan worker thread.",
                            NAME, MB_OK | MB_ICONERROR);
                delete g_worker; g_worker = nullptr;
                SetDialogBusy(hDlg, false);
            }
            return TRUE;
        }
        if (id == IDCANCEL) {
            // Ctrl+Close = "Save as..." file picker -- only when no worker is
            // running. Reads dialog state, prompts for a target .cfg path via
            // GetSaveFileNameW, and saves the current settings there.
            // This is a "save and close" gesture (matches Close's primary role).
            // Use Ctrl+Run to save without closing.
            bool ctrlHeld = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
            if (ctrlHeld && !g_workerThread && s && ctx) {
                // Refuse Save-as while the helper-exe is in the rejected
                // state -- the trufflehog_exe field currently holds the
                // rejected path (ShowHelperRejection echoed it for visual
                // feedback) and persisting it to a file would just spread
                // the poison. Tell the analyst what to do.
                if (g_helperRejected) {
                    Log(L"Save-as refused: helper-exe rejected -- pick a valid trufflehog.exe via Browse before saving");
                    SetDlgItemTextW(hDlg, IDC_LABEL_PROGRESS_STATUS,
                        L"Save-as refused: pick a valid trufflehog.exe first.");
                    return TRUE;
                }
                if (!ReadDialogToSettings(hDlg, *s)) return TRUE;
                wchar_t fileBuf[MAX_PATH] = L"xways-trufflehog.cfg";
                OPENFILENAMEW ofn = {};
                ofn.lStructSize  = sizeof(ofn);
                ofn.hwndOwner    = hDlg;
                ofn.lpstrFilter  = L"Config Files (*.cfg)\0*.cfg\0All files (*.*)\0*.*\0";
                ofn.nFilterIndex = 1;
                ofn.lpstrFile    = fileBuf;
                ofn.nMaxFile     = MAX_PATH;
                ofn.lpstrTitle   = L"Save settings to...";
                ofn.Flags        = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
                ofn.lpstrDefExt  = L"cfg";
                if (!GetSaveFileNameW(&ofn)) return TRUE;  // user cancelled
                bool ok = SaveSettingsToCfg(fileBuf, *s);
                Log(ok ? (L"settings saved via Ctrl+Close (Save as) to: " + std::wstring(fileBuf))
                       : (L"settings save FAILED via Ctrl+Close to: "      + std::wstring(fileBuf)));
                SetDlgItemTextW(hDlg, IDC_LABEL_PROGRESS_STATUS,
                    ok ? L"Settings saved to selected file."
                       : L"Failed to save settings to selected file (see Messages).");
                if (ok) EndDialog(hDlg, IDCANCEL);
                return TRUE;
            }

            if (g_workerThread && g_worker) {
                // First Cancel during run -> request stop. Second click closes.
                if (!g_worker->cancelRequested.load()) {
                    g_worker->cancelRequested.store(true);
                    SetDlgItemTextW(hDlg, IDC_LABEL_PROGRESS_STATUS, L"Cancelling...");
                    return TRUE;
                }
                // Already cancelled but worker still draining -> let user close.
            }
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        return FALSE;
    }

    case WM_APP_PROGRESS: {
        HWND hProg = GetDlgItem(hDlg, IDC_PROGRESS_RUN);
        SendMessageW(hProg, PBM_SETPOS, (WPARAM)(int)wp, 0);
        return TRUE;
    }
    case WM_APP_STATUS: {
        auto* txt = (wchar_t*)lp;
        if (txt) {
            SetDlgItemTextW(hDlg, IDC_LABEL_PROGRESS_STATUS, txt);
            free(txt);
        }
        return TRUE;
    }
    case WM_APP_MARQUEE: {
        HWND hProg = GetDlgItem(hDlg, IDC_PROGRESS_RUN);
        LONG_PTR style = GetWindowLongPtrW(hProg, GWL_STYLE);
        if (wp) {
            SetWindowLongPtrW(hProg, GWL_STYLE, style | PBS_MARQUEE);
            SendMessageW(hProg, PBM_SETMARQUEE, TRUE, 30);
        } else {
            SendMessageW(hProg, PBM_SETMARQUEE, FALSE, 0);
            SetWindowLongPtrW(hProg, GWL_STYLE, style & ~PBS_MARQUEE);
        }
        return TRUE;
    }
    case WM_APP_DONE: {
        if (g_workerThread) {
            WaitForSingleObject(g_workerThread, INFINITE);
            CloseHandle(g_workerThread);
            g_workerThread = nullptr;
        }
        delete g_worker; g_worker = nullptr;
        SetDialogBusy(hDlg, false);
        // Leave the status label visible with the final summary.
        HWND hOpenOutput = GetDlgItem(hDlg, IDC_BTN_OPEN_OUTPUT);
        EnableWindow(hOpenOutput, TRUE);
        // On successful completion (wp == 1): flash the Open-output button to
        // pull the eye, and overlay "Completed" on the (now full) progress
        // bar. On cancel we skip both -- the status label already says
        // "Cancelled: ..." and the progress bar isn't full anyway.
        if (wp == 1) {
            s_openOutputFlashTicks = 8;  // ~1.4s at 180ms/tick, 4 on/off cycles
            SetTimer(hDlg, kFlashTimerId, kFlashPeriodMs, nullptr);
            InvalidateRect(hOpenOutput, nullptr, TRUE);
            HWND hProg = GetDlgItem(hDlg, IDC_PROGRESS_RUN);
            if (hProg) {
                SetWindowSubclass(hProg, ProgressOverlayProc,
                                  kProgressSubclassId, /*refdata*/1);
                InvalidateRect(hProg, nullptr, TRUE);
            }
        }
        return TRUE;
    }
    case WM_APP_VERSION: {
        VersionProbeResult* result = reinterpret_cast<VersionProbeResult*>(lp);
        if (!result) return TRUE;
        // Discard stale results: when the analyst rapidly clicks Browse
        // through several files, slow probes for previous picks may post
        // their results AFTER newer fast probes have already been
        // dispatched. Without this guard, an OLD valid trufflehog probe
        // could arrive after a NEW hindsight rejection and re-enable Run
        // for the WRONG exe (the path in IDC_EDIT_TOOL_BIN is whatever the
        // last Browse landed on).
        if (result->token != g_probeToken.load()) {
            delete result;
            return TRUE;
        }
        if (s) s->trufflehogVersion = result->versionLine;
        if (result->valid) {
            // Accepted. Clear any prior rejection (restores normal font /
            // colour), set the version label, and enable Run.
            ClearHelperRejection(hDlg);
            std::wstring label = L"Version: " + (result->versionLine.empty()
                                                  ? std::wstring(L"(detected)")
                                                  : result->versionLine);
            SetDlgItemTextW(hDlg, IDC_LABEL_TOOL_VERSION, label.c_str());
            g_exeValid = true;
            Log(L"helper-exe accepted (" + result->exe + L") -- " + result->detail);
            EnableWindow(GetDlgItem(hDlg, IDC_BTN_RUN),
                         g_workerThread ? FALSE : TRUE);
        } else {
            // Rejected. Pick a label that matches the failure mode --
            // "File not found" vs "Not a valid trufflehog.exe file" --
            // so the analyst knows whether to find the file or pick a
            // different binary. ShowHelperRejection handles the rest
            // (flash, disable Run, log).
            const wchar_t* label = result->fileExists
                ? kHelperRejectionMessage
                : kHelperMissingMessage;
            ShowHelperRejection(hDlg, result->exe, result->detail, label);
        }
        delete result;
        return TRUE;
    }
    case WM_CLOSE:
        if (g_workerThread && g_worker && !g_worker->cancelRequested.load()) {
            g_worker->cancelRequested.store(true);
            SetDlgItemTextW(hDlg, IDC_LABEL_PROGRESS_STATUS, L"Cancelling...");
            return TRUE;
        }
        EndDialog(hDlg, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

static INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM) {
    switch (msg) {
    case WM_INITDIALOG: {
        ApplyTitleIcon(hDlg);
        std::wstring title = NAME; title += L"  "; title += VERSION;
        SetDlgItemTextW(hDlg, IDC_ABOUT_TITLE, title.c_str());
        SetDlgItemTextW(hDlg, IDC_ABOUT_AUTHOR,
                        L"Kevin Stokes - Digital Detective and Cyber Sleuth");
        // Bold the title + "Author:" prefix to mirror xways-updater's
        // visual rhythm. EnsureBoldFont reuses the dialog's existing
        // bold cache.
        HFONT hBold = EnsureBoldFont(hDlg);
        if (hBold) {
            SendDlgItemMessageW(hDlg, IDC_ABOUT_TITLE,
                                WM_SETFONT, (WPARAM)hBold, TRUE);
            SendDlgItemMessageW(hDlg, IDC_ABOUT_LABEL_AUTHOR_PREFIX,
                                WM_SETFONT, (WPARAM)hBold, TRUE);
        }
        // Coffee button label -- exact match for xways-updater. Set
        // programmatically (not in the .rc) so we don't depend on
        // rc.exe's input codepage to encode U+2665 BLACK HEART SUIT
        // correctly. Updater pattern at x-tensions/xways-updater/xways-updater.cpp:4122.
        SetDlgItemTextW(hDlg, IDC_ABOUT_BTN_COFFEE,
            L"♥ Love this? How about a coffee ♥");
        // Tooltip on the coffee button -- shows the destination URL on
        // hover so the analyst can preview before clicking. Same
        // pattern as xways-updater.
        {
            INITCOMMONCONTROLSEX icc{};
            icc.dwSize = sizeof(icc);
            icc.dwICC  = ICC_BAR_CLASSES;
            InitCommonControlsEx(&icc);
            HWND hTip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASS, nullptr,
                WS_POPUP | TTS_ALWAYSTIP | TTS_BALLOON,
                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                hDlg, nullptr, g_hSelf, nullptr);
            if (hTip) {
                static const wchar_t* kCoffeeTip =
                    L"Opens https://buymeacoffee.com/dfirkev";
                TOOLINFOW ti{};
                ti.cbSize   = sizeof(ti);
                ti.uFlags   = TTF_IDISHWND | TTF_SUBCLASS;
                ti.hwnd     = hDlg;
                ti.uId      = (UINT_PTR)GetDlgItem(hDlg, IDC_ABOUT_BTN_COFFEE);
                ti.lpszText = (LPWSTR)kCoffeeTip;
                SendMessageW(hTip, TTM_ADDTOOL, 0, (LPARAM)&ti);
                SendMessageW(hTip, TTM_SETMAXTIPWIDTH, 0, 360);
            }
        }
        return TRUE;
    }
    case WM_COMMAND: {
        WORD id = LOWORD(wp);
        if (id == IDOK || id == IDCANCEL) {
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        if (id == IDC_ABOUT_LINK_GITHUB) {
            ShellExecuteW(hDlg, L"open",
                L"https://github.com/kev365/xways-trufflehog",
                nullptr, nullptr, SW_SHOWNORMAL);
            return TRUE;
        }
        if (id == IDC_ABOUT_LINK_LINKEDIN) {
            ShellExecuteW(hDlg, L"open",
                L"https://www.linkedin.com/in/dfir-kev",
                nullptr, nullptr, SW_SHOWNORMAL);
            return TRUE;
        }
        if (id == IDC_ABOUT_BTN_COFFEE) {
            ShellExecuteW(hDlg, L"open",
                L"https://buymeacoffee.com/dfirkev",
                nullptr, nullptr, SW_SHOWNORMAL);
            return TRUE;
        }
        return FALSE;
    }
    case WM_CLOSE:
        EndDialog(hDlg, IDOK);
        return TRUE;
    }
    return FALSE;
}

// =============================================================================
//  ShowDialogAndRun — top-level entry from XT_Finalize
// =============================================================================
//   Receives the X-Ways-collected item list (filter-respected for RUN mode,
//   selection-respected for DBC). Loads cfg defaults, populates the dialog,
//   waits for the user to click Run, then runs the scan in the worker.
static void ShowDialogAndRun(const Collected& c) {
    Settings s;
    std::wstring cfgPath = GetSelfDirectory() + L"\\xways-trufflehog.cfg";
    EnsureCfgExists(cfgPath);   // creates from .example or embedded defaults if absent
    LoadCfg(cfgPath, s);
    if (s.trufflehogExe.empty()) s.trufflehogExe = ResolveDefaultTrufflehog();
    // Version probe is deferred to a worker thread kicked off in WM_INITDIALOG
    // (StartAsyncVersionProbe). Running it synchronously here stacks a ~2-5s
    // subprocess wait onto the X-Ways DBC per-item enumeration freeze before
    // the dialog can paint -- enough total "Not Responding" time that Windows
    // or the analyst may kill X-Ways.
    // Output base resolution: always default to the currently-open case root.
    // Re-resolve at every dialog open so a cfg-persisted path from a prior case
    // doesn't pin output to the wrong folder when the analyst switches cases.
    // An analyst's in-case customization (e.g. setting output to
    // <case>\custom\trufflehog\) is preserved -- we only override the cfg
    // value when it points outside the current case directory.
    {
        std::wstring caseDir = GetCaseDirectory();
        bool cfgPathIsForDifferentCase = !caseDir.empty() && !s.outputBase.empty() &&
            (s.outputBase.size() < caseDir.size() ||
             _wcsnicmp(s.outputBase.c_str(), caseDir.c_str(), caseDir.size()) != 0);
        if (s.outputBase.empty() || cfgPathIsForDifferentCase) {
            std::wstring src;
            s.outputBase = ResolveDefaultOutputBase(c.hEvidence, src);
        }
    }
    // Default prefilter-extensions list -- media + compiled artifacts +
    // archives. Power users edit the dialog or the cfg. Pre-set only if
    // cfg didn't say anything (empty); explicit empty-cfg meaning "scan
    // all extensions" is achievable by setting `prefilter_extensions=` to
    // a single space character.
    if (s.prefilterExtensions.empty()) {
        s.prefilterExtensions =
            L"jpg,jpeg,png,gif,bmp,tiff,tif,webp,svg,ico,heic,heif,raw,"
            L"mp3,mp4,mov,avi,mkv,wav,flac,ogg,m4a,m4v,wmv,"
            L"iso,dmg,vmdk,vhd,vhdx,qcow2,"
            L"exe,dll,sys,obj,o,a,so,pdb,class,jar,"
            L"zip,7z,gz,tar,rar,xz,bz2,lz4,zst";
    }

    RunCtx ctx;
    ctx.hVolume        = c.hVolume;
    ctx.hEvidence      = c.hEvidence;
    ctx.invocationMode = c.invocationMode;
    ctx.items          = c.items;
    // Pre-classify items so the dialog can show a count that matches what
    // we'll actually scan. X-Ways calls XT_ProcessItem for every item in
    // scope including the directory items themselves; ShouldScan filters
    // those at scan time, but the analyst should see the split up front so
    // the count doesn't look inflated vs. the X-Ways "Selected: N files"
    // status line. One XWF_GetItemInformation call per item (sub-microsecond)
    // so even 100k items is well under 100ms.
    if (XWF_GetItemInformation) {
        for (LONG id : ctx.items) {
            BOOL valid = FALSE;
            LONG flags = (LONG)XWF_GetItemInformation(id, XWF_ITEM_INFO_FLAGS, &valid);
            if (valid && (flags & XWF_ITEM_INFO_FLAG_DIRECTORY)) ++ctx.dirCount;
        }
    }

    if (!ctx.hVolume) {
        MessageBoxW(g_hMainWnd,
            L"xways-trufflehog needs a volume handle to read item bytes, but X-Ways "
            L"did not provide one. This happens when the X-Tension is invoked from "
            L"the Case Root window.\n\nRun the X-Tension from inside a partition or "
            L"image Directory Browser instead.",
            NAME, MB_OK | MB_ICONWARNING);
        return;
    }
    if (ctx.items.empty()) {
        MessageBoxW(g_hMainWnd,
            L"No items in scope.\n\nEither nothing was selected, or the active "
            L"X-Ways filter excluded every item in this view.",
            NAME, MB_OK | MB_ICONINFORMATION);
        return;
    }

    std::pair<Settings*, RunCtx*> lp(&s, &ctx);
    DialogBoxParamW(g_hSelf, MAKEINTRESOURCEW(IDD_SETTINGS),
                    g_hMainWnd ? g_hMainWnd : GetActiveWindow(),
                    SettingsDlgProc, (LPARAM)&lp);
}

// =============================================================================
//  Entry points
// =============================================================================
extern "C" {

LONG __stdcall XT_Init(DWORD nVersion, DWORD /*nFlags*/, HWND hMainWnd, void*) {
    g_hMainWnd = hMainWnd;
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    // ICC_BAR_CLASSES registers TOOLTIPS_CLASS (along with toolbar/statusbar/trackbar)
    // so the per-control tooltips on the settings dialog work.
    icc.dwICC  = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);

    int missing = RetrieveFunctionPointers();
    Log(FormatW(L"%s %s \x2014 X-Ways build %.2f, %d missing exports",
                NAME, VERSION, nVersion / 100.0, missing));
    if (missing > 0) {
        Log(L"required XWF_* exports are missing \x2014 refusing to load");
        return -1;
    }
    return 1;
}

LONG __stdcall XT_About(HWND hParentWnd, void*) {
    std::wstring m = NAME; m += L" "; m += VERSION; m += L" \x2014 "; m += DESCRIPTION;
    if (XWF_OutputMessage) XWF_OutputMessage(m.c_str(), 0);
    DialogBoxParamW(g_hSelf, MAKEINTRESOURCEW(IDD_ABOUT),
                    hParentWnd ? hParentWnd : g_hMainWnd, AboutDlgProc, 0);
    return 0;
}

LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, void*) {
    wchar_t volName[260] = {0};
    if (hVolume && XWF_GetVolumeName) XWF_GetVolumeName(hVolume, volName, 0);
    Log(FormatW(L"XT_Prepare op=%lu volume=%s", (unsigned long)nOpType,
                volName[0] ? volName : L"(none)"));

    // Both Run and DBC modes use the same collection path -- request
    // XT_ProcessItem callbacks for the item set X-Ways enumerates. In RUN
    // mode that honors the analyst's active filter; in DBC mode it's the
    // right-clicked selection. Dialog opens in XT_Finalize once the list
    // is complete.
    g_collected = Collected{};
    g_collected.ready          = true;
    g_collected.hVolume        = hVolume;
    g_collected.hEvidence      = hEvidence;
    g_collected.invocationMode = (nOpType == XT_ACTION_DBC)
        ? InvocationMode::Selection : InvocationMode::Run;
    return 0x01;  // request XT_ProcessItem callbacks
}

LONG __stdcall XT_ProcessItem(LONG nItemID, void*) {
    if (!g_collected.ready) return 0;
    g_collected.items.push_back(nItemID);

    // Every 1024 items, tickle Windows' responsiveness timer AND check whether
    // the analyst has asked to abort. The freeze itself is unavoidable (X-Ways
    // drives the loop on the main UI thread), but these two checks together
    // make it survivable:
    //
    //   1. PeekMessage(PM_NOREMOVE) — resets the "Not Responding" timer per
    //      IsHungAppWindow docs without dispatching anything (no re-entrancy
    //      risk vs. X-Ways' enumeration loop). Prevents Windows from offering
    //      to terminate the host during a long enumeration.
    //      https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-ishungappwindow
    //
    //   2. XWF_ShouldStop — returns TRUE when the analyst clicks X-Ways' Stop
    //      button or presses Esc. Returning a negative value here tells X-Ways
    //      to stop calling us; XT_Finalize will still fire (with the partial
    //      set) but it checks the aborted flag and skips the dialog.
    if ((g_collected.items.size() & 0x3FF) == 0) {
        MSG msg;
        PeekMessageW(&msg, nullptr, 0, 0, PM_NOREMOVE);
        if (XWF_ShouldStop && XWF_ShouldStop()) {
            g_collected.aborted = true;
            Log(FormatW(L"enumeration aborted by user after %zu item(s)",
                        g_collected.items.size()));
            return -1;  // abort iteration
        }
    }
    return 0;
}

LONG __stdcall XT_ProcessItemEx(LONG, HANDLE, void*) { return 0; }
LONG __stdcall XT_ProcessSearchHit(void*) { return 0; }

LONG __stdcall XT_Finalize(HANDLE, HANDLE, DWORD, void*) {
    if (g_collected.ready) {
        if (g_collected.aborted) {
            // User aborted enumeration mid-flight (e.g. realised they selected
            // far too many items). Don't open the dialog with a partial set --
            // just bail. The Log line in XT_ProcessItem already announced the
            // abort.
            Log(L"skipping dialog: enumeration was aborted before completion");
        } else {
            ShowDialogAndRun(g_collected);
        }
        g_collected = Collected{};
    }
    return 0;
}

LONG __stdcall XT_Done(void*) { Log(L"XT_Done"); return 0; }

} // extern "C"

// =============================================================================
//  Manager-plugin integration (xways-xt-manager)
// =============================================================================
//   Lets the SAME DLL load as a plugin under xways-xt-manager. The manager
//   finds us via the XwaysManagerPluginEntry export below. The On* callbacks
//   delegate to the EXISTING standalone internals (RetrieveFunctionPointers,
//   LoadCfg, the worker batch pipeline) — managed mode never shows the modal
//   settings dialog; the embedded tab the manager already hosts handles
//   settings, and TrufflehogHarvestSettings reads them back.
//
//   Run model bridge (see the g_managed_* comment block near g_collected):
//   trufflehog is a per-item-COLLECT + BATCH-SCAN tool. The scan itself runs
//   inside WorkerThread (extract item chunks -> invoke trufflehog.exe once per
//   chunk -> parse JSONL -> tag). Standalone launches WorkerThread on a
//   separate thread from the dialog's Run button and pumps WM_APP_* progress
//   back to the dialog. Managed mode has no trufflehog-owned message loop, so
//   we run WorkerThread SYNCHRONOUSLY on the manager's calling thread with
//   hDlg=NULL — every Post*()/PostMessageW() is a guarded no-op when hDlg is
//   NULL, so the worker completes inline and returns. (Mirrors how
//   xways-ual-timeliner-xtmgr's UalOnPrepare calls WorkerEntry synchronously.)
//
//   Why OnFinalize runs the scan (not OnPrepare): trufflehog scans the exact
//   filter-respected item set X-Ways enumerates via the per-item callbacks,
//   which is only complete after the last OnProcessItem fires — i.e. at
//   finalize. hindsight / ual-timeliner instead discover their own items
//   inside OnPrepare and run there.

#include "manager-plugin.h"

static bool __stdcall TrufflehogOnInit(HMODULE, HWND hMainWnd, void*) {
    g_hMainWnd = hMainWnd;

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);

    int missing = RetrieveFunctionPointers();
    Log(FormatW(L"%s %s \x2014 managed mode via xways-xt-manager (%d missing exports)",
                NAME, VERSION, missing));
    if (missing > 0) {
        Log(L"required XWF_* exports missing \x2014 plugin disabled");
        return false;
    }

    g_managed_mode = true;
    // Prime managed settings from the sidecar cfg so the embedded dialog has
    // something to show at first open and a cfg-only managed run (analyst
    // never touches the tab) still works end-to-end.
    std::wstring cfgPath = GetSelfDirectory() + L"\\xways-trufflehog.cfg";
    EnsureCfgExists(cfgPath);
    LoadCfg(cfgPath, g_managed_settings);
    if (g_managed_settings.trufflehogExe.empty())
        g_managed_settings.trufflehogExe = ResolveDefaultTrufflehog();
    // Point the dialog-fallback RunCtx at sane defaults for first display.
    g_managed_runctx = RunCtx{};
    return true;
}

static void __stdcall TrufflehogHarvestSettings(HWND hEmbeddedDlg, void*) {
    if (!hEmbeddedDlg) return;
    // Reuse the standalone control->Settings reader. ReadDialogToSettings may
    // pop a MessageBox + return false if the exe field is empty/missing; in
    // managed mode we still want whatever the analyst typed for the OTHER
    // fields, so read the exe path ourselves first (no modal), then let
    // ReadDialogToSettings fill the rest. If it bails on the exe gate, the
    // fields it already wrote (none, since the exe check is first) are
    // unaffected — so we mirror its body for the exe and call it for the rest.
    wchar_t buf[1024] = {0};
    GetDlgItemTextW(hEmbeddedDlg, IDC_EDIT_TOOL_BIN, buf, _countof(buf));
    g_managed_settings.trufflehogExe = TrimW(buf);

    // ReadDialogToSettings's only early-out is the exe-existence gate. When the
    // exe IS valid it reads every field; when it's not, it returns false after
    // showing a warning. To avoid a modal during harvest AND still capture all
    // fields, temporarily satisfy the gate check by reading the rest directly
    // only when the exe is missing; otherwise delegate to the shared reader.
    if (!g_managed_settings.trufflehogExe.empty() &&
        FileExists(g_managed_settings.trufflehogExe)) {
        // Valid exe -> shared reader fills every field (it re-reads the exe,
        // which matches what we set above).
        ReadDialogToSettings(hEmbeddedDlg, g_managed_settings);
    } else {
        // No valid exe yet (analyst still configuring). Read the non-exe
        // fields directly so their choices aren't lost, skipping the modal.
        GetDlgItemTextW(hEmbeddedDlg, IDC_EDIT_OUTPUT_DIR, buf, _countof(buf));
        g_managed_settings.outputBase = TrimW(buf);
        GetDlgItemTextW(hEmbeddedDlg, IDC_EDIT_MIN_SIZE, buf, _countof(buf));
        g_managed_settings.minSizeBytes = ParseInt64(buf, 1);
        if (g_managed_settings.minSizeBytes < 0) g_managed_settings.minSizeBytes = 0;
        GetDlgItemTextW(hEmbeddedDlg, IDC_EDIT_MAX_SIZE, buf, _countof(buf));
        g_managed_settings.maxSizeMiB = ParseInt64(buf, 256);
        if (g_managed_settings.maxSizeMiB < 0) g_managed_settings.maxSizeMiB = 0;
        g_managed_settings.forceSkipBinaries =
            IsDlgButtonChecked(hEmbeddedDlg, IDC_CHK_SKIP_BINARIES) == BST_CHECKED;
        GetDlgItemTextW(hEmbeddedDlg, IDC_EDIT_FILTER_ENTROPY, buf, _countof(buf));
        g_managed_settings.filterEntropy = TrimW(buf);
        GetDlgItemTextW(hEmbeddedDlg, IDC_EDIT_PREFILTER_EXT, buf, _countof(buf));
        g_managed_settings.prefilterExtensions = TrimW(buf);
        GetDlgItemTextW(hEmbeddedDlg, IDC_EDIT_INCLUDE_DETECTORS, buf, _countof(buf));
        g_managed_settings.includeDetectors = TrimW(buf);
        GetDlgItemTextW(hEmbeddedDlg, IDC_EDIT_EXCLUDE_DETECTORS, buf, _countof(buf));
        g_managed_settings.excludeDetectors = TrimW(buf);
        GetDlgItemTextW(hEmbeddedDlg, IDC_EDIT_EXTRA_ARGS, buf, _countof(buf));
        g_managed_settings.extraArgs = TrimW(buf);
        g_managed_settings.verbose =
            IsDlgButtonChecked(hEmbeddedDlg, IDC_CHK_VERBOSE) == BST_CHECKED;
    }

    // Persist immediately so the next session inherits the analyst's choices,
    // matching the standalone IDOK behaviour (which also saves on Run).
    std::wstring cfgPath = GetSelfDirectory() + L"\\xways-trufflehog.cfg";
    if (!SaveSettingsToCfg(cfgPath, g_managed_settings))
        Log(L"warning: could not save cfg from managed harvest to " + cfgPath);
}

static bool __stdcall TrufflehogOnPrepare(HANDLE hVolume, HANDLE hEvidence,
                                          DWORD nOpType, void*) {
    // Stash handles + reset the collector. Return true so the manager fans out
    // per-item callbacks; the actual scan runs in TrufflehogOnFinalize once
    // the filter-respected item set is complete.
    g_managed_collected = Collected{};
    g_managed_collected.ready          = true;
    g_managed_collected.hVolume        = hVolume;
    g_managed_collected.hEvidence      = hEvidence;
    g_managed_collected.invocationMode = (nOpType == XT_ACTION_DBC)
        ? InvocationMode::Selection : InvocationMode::Run;
    wchar_t volName[260] = {0};
    if (hVolume && XWF_GetVolumeName) XWF_GetVolumeName(hVolume, volName, 0);
    Log(FormatW(L"managed OnPrepare op=%lu volume=%s", (unsigned long)nOpType,
                volName[0] ? volName : L"(none)"));
    return true;
}

static LONG __stdcall TrufflehogOnProcessItem(LONG nItemID, HANDLE, void*) {
    // Mirror standalone XT_ProcessItem's collection (the manager owns the
    // PeekMessage/abort plumbing, so we just accumulate here).
    if (!g_managed_collected.ready) return 0;
    g_managed_collected.items.push_back(nItemID);
    return 0;
}

static bool __stdcall TrufflehogOnFinalize(HANDLE hVolume, HANDLE hEvidence,
                                           DWORD /*nOpType*/, void*) {
    if (!g_managed_collected.ready) return true;

    // ---- Build the Settings for this run from the harvested managed state.
    Settings s = g_managed_settings;
    if (s.trufflehogExe.empty()) s.trufflehogExe = ResolveDefaultTrufflehog();
    if (s.trufflehogExe.empty() || !FileExists(s.trufflehogExe)) {
        Log(L"trufflehog.exe not found \x2014 set 'trufflehog_exe' in the cfg or "
            L"the TruffleHog tab, or drop trufflehog.exe next to the DLL");
        g_managed_collected = Collected{};
        return false;
    }
    // Helper-exe identity gate: the standalone dialog confirms the binary
    // identifies as TruffleHog via the canonical PE VERSIONINFO + --version
    // banner check (PeIdentityContains || banner substring) before enabling
    // Run. Managed mode has no dialog to flash, so we just verify, log, and
    // bail on rejection.
    {
        std::wstring versionLine, detail;
        bool ok = VerifyHelperIdentity(s.trufflehogExe, kHelperIdentityNeedle,
                                       versionLine, detail);
        if (!ok) {
            Log(L"helper-exe REJECTED (" + s.trufflehogExe + L") -- " + detail +
                L" -- refusing to run");
            g_managed_collected = Collected{};
            return false;
        }
        Log(L"helper-exe accepted (" + s.trufflehogExe + L") -- " + detail);
        s.trufflehogVersion = versionLine;
    }

    // Output base: default to the current case's <case>\xways-trufflehog when
    // the harvested/cfg value is empty or points outside the current case
    // (same logic as ShowDialogAndRun).
    {
        std::wstring caseDir = GetCaseDirectory();
        bool cfgPathIsForDifferentCase = !caseDir.empty() && !s.outputBase.empty() &&
            (s.outputBase.size() < caseDir.size() ||
             _wcsnicmp(s.outputBase.c_str(), caseDir.c_str(), caseDir.size()) != 0);
        if (s.outputBase.empty() || cfgPathIsForDifferentCase) {
            std::wstring src;
            s.outputBase = ResolveDefaultOutputBase(hEvidence, src);
        }
    }
    // Prefilter-extensions default (matches ShowDialogAndRun).
    if (s.prefilterExtensions.empty()) {
        s.prefilterExtensions =
            L"jpg,jpeg,png,gif,bmp,tiff,tif,webp,svg,ico,heic,heif,raw,"
            L"mp3,mp4,mov,avi,mkv,wav,flac,ogg,m4a,m4v,wmv,"
            L"iso,dmg,vmdk,vhd,vhdx,qcow2,"
            L"exe,dll,sys,obj,o,a,so,pdb,class,jar,"
            L"zip,7z,gz,tar,rar,xz,bz2,lz4,zst";
    }

    // ---- Build the RunCtx the worker consumes.
    RunCtx ctx;
    ctx.hVolume        = hVolume ? hVolume : g_managed_collected.hVolume;
    ctx.hEvidence      = hEvidence ? hEvidence : g_managed_collected.hEvidence;
    ctx.invocationMode = g_managed_collected.invocationMode;
    ctx.items          = g_managed_collected.items;

    if (!ctx.hVolume) {
        Log(L"managed run needs a volume handle to read item bytes, but X-Ways "
            L"did not provide one (Case Root window?). Run inside a partition / "
            L"image instead.");
        g_managed_collected = Collected{};
        return false;
    }
    if (ctx.items.empty()) {
        Log(L"managed run: no items in scope (nothing selected or filter "
            L"excluded everything)");
        g_managed_collected = Collected{};
        return true;
    }

    Log(FormatW(L"managed run: scanning %zu item(s) with %s",
                ctx.items.size(), s.trufflehogVersion.c_str()));

    // ---- Run the batch worker SYNCHRONOUSLY on this (manager) thread.
    //   hDlg=NULL routes every Post*/PostMessageW to a no-op; WorkerThread
    //   does not self-join or touch g_worker/g_workerThread, so a local
    //   WorkerCtx is fully self-contained. Logs stream to the Messages window.
    WorkerCtx w;
    w.s    = &s;
    w.ctx  = &ctx;
    w.hDlg = nullptr;
    WorkerThread(&w);   // returns when the scan + findings export complete

    g_managed_collected = Collected{};
    return true;
}

extern "C" __declspec(dllexport)
const XwaysManagerPluginDescriptor* __stdcall XwaysManagerPluginEntry(void) {
    static const XwaysManagerPluginDescriptor desc = {
        XWAYS_MANAGER_PLUGIN_ABI_VERSION,
        sizeof(XwaysManagerPluginDescriptor),

        L"xways-trufflehog",
        L"TruffleHog",
        L"Secret scanner. Extracts in-scope items + runs trufflehog over them "
        L"in batches + tags findings in a Report Table.",
        VERSION,

        IDD_SETTINGS,   // tab_dialog_resource_id (Option A — manager retrofits styles at embed time)
        0,              // tab_dialog_embedded_resource_id (Option B; 0 = use Option A path)
        SettingsDlgProc,

        TrufflehogOnInit,
        TrufflehogOnPrepare,
        TrufflehogOnProcessItem, // on_process_item: collect item IDs (matches
                                 // standalone XT_ProcessItem; manager requests
                                 // X-Ways flag 0x01 because this is non-NULL)
        nullptr,                 // on_process_item_ex: not used (no per-item handle needed)
        TrufflehogOnFinalize,    // batch scan runs here

        true,           // default_enabled
        nullptr,        // reserved

        // -------- Post-v1 additive fields --------
        TrufflehogHarvestSettings
    };
    return &desc;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) g_hSelf = hModule;
    return TRUE;
}
