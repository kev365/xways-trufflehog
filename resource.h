// =============================================================================
//  resource.h — control IDs for xways-trufflehog dialogs
//
//  Numbering convention per docs/xtension-dialog-conventions.md:
//    100..199  dialog template + primary control IDs
//    200..299  per-X-Tension labels / extras
// =============================================================================
#pragma once

// --- Dialog template -------------------------------------------------------
#define IDD_SETTINGS                       100
#define IDD_ABOUT                          101

// --- Header ----------------------------------------------------------------
#define IDC_LABEL_HEADER                   102

// --- TruffleHog binary group -----------------------------------------------
#define IDC_GROUP_TOOL                     110
#define IDC_LABEL_TOOL_BIN                 111
#define IDC_EDIT_TOOL_BIN                  112
#define IDC_BTN_BROWSE_TOOL                113
#define IDC_LABEL_TOOL_VERSION             114

// --- Input scope group -----------------------------------------------------
#define IDC_GROUP_INPUT                    120
#define IDC_RADIO_INPUT_AUTO               121   // "All items in snapshot"
#define IDC_RADIO_INPUT_SELECTED           122   // "Selected items (N)"
#define IDC_LABEL_MIN_SIZE                 123
#define IDC_EDIT_MIN_SIZE                  124
#define IDC_LABEL_MAX_SIZE                 125
#define IDC_EDIT_MAX_SIZE                  126
#define IDC_LABEL_SELECTED_COUNT           127   // prefix "Items to scan:" (regular weight)
#define IDC_LABEL_SELECTED_COUNT_NUM       128   // bold middle "N files (+ M dirs ...)"
#define IDC_LABEL_SELECTED_COUNT_TAIL      129   // regular tail "from right-click; X-Ways filter respected"

// --- Verification group ----------------------------------------------------
#define IDC_GROUP_VERIFY                   130
#define IDC_RADIO_VERIFY_NONE              131
#define IDC_RADIO_VERIFY_ALL               132
#define IDC_RADIO_VERIFY_ONLY              133
#define IDC_LABEL_VERIFY                   134
#define IDC_COMBO_VERIFY                   135   // 0=None, 1=All, 2=OnlyVerified

// --- Advanced Settings group -----------------------------------------------
#define IDC_GROUP_OPTIONS                  140
#define IDC_LABEL_INCLUDE_DETECTORS        141
#define IDC_EDIT_INCLUDE_DETECTORS         142
#define IDC_LABEL_EXCLUDE_DETECTORS        143
#define IDC_EDIT_EXCLUDE_DETECTORS         144
#define IDC_LABEL_LOG_LEVEL                145
#define IDC_COMBO_LOG_LEVEL                146
#define IDC_LABEL_CONCURRENCY              147
#define IDC_EDIT_CONCURRENCY               148
#define IDC_COMBO_CONCURRENCY              151   // CBS_DROPDOWNLIST: Auto + powers of 2 up to host CPU count
#define IDC_LABEL_EXTRA_ARGS               149
#define IDC_EDIT_EXTRA_ARGS                150

// --- Output group ----------------------------------------------------------
#define IDC_GROUP_OUTPUT                   160
#define IDC_LABEL_OUTPUT_DIR               161
#define IDC_EDIT_OUTPUT_DIR                162
#define IDC_BTN_BROWSE_OUTPUT              163
#define IDC_CHK_KEEP_EXTRACTED             164
#define IDC_CHK_ADD_REPORT_TABLE           165
#define IDC_CHK_ADD_COMMENT                166
#define IDC_LABEL_TAG_THRESHOLD            167
#define IDC_EDIT_TAG_THRESHOLD             168
#define IDC_CHK_VERBOSE                    169
#define IDC_CHK_FINDINGS_TSV               177    // BS_AUTO3STATE: off / redacted / full
#define IDC_LABEL_FINDINGS_TSV             178
#define IDC_LABEL_SPLIT_ROWS               186    // "Split after"
#define IDC_EDIT_SPLIT_ROWS                187    // numeric input, default 500000
#define IDC_LABEL_SPLIT_ROWS_TAIL          188    // "rows"
#define IDC_CHK_SKIP_BINARIES              170
#define IDC_LABEL_FILTER_ENTROPY           171
#define IDC_EDIT_FILTER_ENTROPY            172
#define IDC_LABEL_PREFILTER_EXT            173
#define IDC_EDIT_PREFILTER_EXT             174
#define IDC_LABEL_BATCH_SIZE               175
#define IDC_EDIT_BATCH_SIZE                176

// --- Status group + action row ---------------------------------------------
#define IDC_GROUP_STATUS                   179   // wraps the status label + progress bar
#define IDC_LABEL_PROGRESS_STATUS          180
#define IDC_PROGRESS_RUN                   181
#define IDC_BTN_ABOUT                      182
#define IDC_BTN_OPEN_OUTPUT                183
#define IDC_BTN_RUN                        184    // DEFPUSHBUTTON — IDOK
#define IDC_BTN_OPEN_CFG                   185

// --- About dialog ----------------------------------------------------------
#define IDC_ABOUT_TITLE                    190
#define IDC_ABOUT_DESC                     191
#define IDC_ABOUT_AUTHOR                   192
#define IDC_ABOUT_LINK                     193
#define IDC_ABOUT_LABEL_AUTHOR_PREFIX      194   // "Author:" bold prefix
#define IDC_ABOUT_LINK_GITHUB              195
#define IDC_ABOUT_LINK_LINKEDIN            196
#define IDC_ABOUT_BTN_COFFEE               197
