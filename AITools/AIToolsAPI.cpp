#include "AIToolsAPI.h"
#include "DebuggerAPI.h"
#include "json.hpp"

#include <string>
#include <cstring>
#include <cstdlib>
#include <map>
#include <functional>
#include <algorithm>
#include <set>

// ---------------------------------------------------------------------------
// Module-level state
// ---------------------------------------------------------------------------
static HANDLE g_hProcess   = NULL;
static DWORD  g_dwPid      = 0;
static DWORD  g_dwCurrentThreadId = 0;

static std::string ToUpperCopy(const std::string& s);

static bool TryParseHexAddress(const std::string& addrStr, DWORD& outAddr)
{
    outAddr = 0;
    if (addrStr.empty()) return false;
    if (addrStr.compare(0, 2, "0x") == 0 || addrStr.compare(0, 2, "0X") == 0)
        outAddr = (DWORD)strtoul(addrStr.c_str() + 2, nullptr, 16);
    else
        outAddr = (DWORD)strtoul(addrStr.c_str(), nullptr, 16);
    return outAddr != 0;
}

static bool FindContainingFunction(DWORD address, FunctionAnalysisInfo* outInfo)
{
    if (!outInfo) return false;
    int count = dbg_GetFunctionAnalysisCount();
    for (int i = 0; i < count; ++i)
    {
        FunctionAnalysisInfo info = { 0 };
        if (!dbg_GetFunctionAnalysisItem(i, &info))
            continue;
        if (address >= info.startAddr && address <= info.endAddr)
        {
            *outInfo = info;
            return true;
        }
    }
    return false;
}

static bool EnsureFunctionAnalysisForAddress(DWORD address, FunctionAnalysisInfo* outInfo)
{
    FunctionAnalysisInfo info = { 0 };
    if (FindContainingFunction(address, &info))
    {
        if (outInfo) *outInfo = info;
        return true;
    }

    dbg_AnalyzeFunctions();

    if (!FindContainingFunction(address, &info))
        return false;

    if (outInfo) *outInfo = info;
    return true;
}

static bool TryGetFunctionRangeForAddress(DWORD address, int* outStartIndex, int* outEndIndex, FunctionAnalysisInfo* outFuncInfo)
{
    if (!outStartIndex || !outEndIndex) return false;

    dbg_EnsureDisasm(address);

    FunctionAnalysisInfo func = { 0 };
    if (EnsureFunctionAnalysisForAddress(address, &func))
    {
        int startIndex = dbg_FindDisasmIndexByAddr(func.startAddr);
        int endIndex = dbg_FindDisasmIndexByAddr(func.endAddr);
        if (startIndex >= 0 && endIndex >= startIndex)
        {
            *outStartIndex = startIndex;
            *outEndIndex = endIndex;
            if (outFuncInfo) *outFuncInfo = func;
            return true;
        }
    }

    const int total = dbg_GetGlobalDisasmCount();
    const int hitIndex = dbg_FindDisasmIndexByAddr(address);
    if (total <= 0 || hitIndex < 0)
        return false;

    int startIndex = hitIndex;
    for (int i = hitIndex - 1, scanned = 0; i >= 0 && scanned < 96; --i, ++scanned)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            break;

        const std::string asmUpper = ToUpperCopy(std::string(info.assembly));
        const std::string cmtUpper = ToUpperCopy(info.comment);
        if (cmtUpper.find("AI FUNC ") != std::string::npos)
        {
            startIndex = i;
            break;
        }

        if (asmUpper.rfind("RET", 0) == 0)
        {
            startIndex = i + 1;
            break;
        }

        startIndex = i;
    }

    int endIndex = hitIndex;
    for (int i = hitIndex, scanned = 0; i < total && scanned < 160; ++i, ++scanned)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            break;

        endIndex = i;
        const std::string asmUpper = ToUpperCopy(std::string(info.assembly));
        const std::string cmtUpper = ToUpperCopy(info.comment);
        if (i > hitIndex && cmtUpper.find("AI FUNC ") != std::string::npos)
        {
            endIndex = i - 1;
            break;
        }

        if (asmUpper.rfind("RET", 0) == 0)
            break;
    }

    InstrInfo startInfo = { 0 };
    InstrInfo endInfo = { 0 };
    if (!dbg_GetGlobalDisasmItem(startIndex, &startInfo) || !dbg_GetGlobalDisasmItem(endIndex, &endInfo))
        return false;

    *outStartIndex = startIndex;
    *outEndIndex = endIndex;
    if (outFuncInfo)
    {
        memset(outFuncInfo, 0, sizeof(*outFuncInfo));
        outFuncInfo->startAddr = startInfo.address;
        outFuncInfo->endAddr = endInfo.address;
        sprintf_s(outFuncInfo->name, sizeof(outFuncInfo->name), "sub_%08X", startInfo.address);
        strncpy_s(outFuncInfo->signature, sizeof(outFuncInfo->signature), "local range fallback", _TRUNCATE);
        strncpy_s(outFuncInfo->feature, sizeof(outFuncInfo->feature), "General (fallback)", _TRUNCATE);
    }
    return true;
}

static std::string ToUpperCopy(const std::string& s)
{
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return (char)toupper(c); });
    return out;
}

static std::string TrimAscii(const std::string& text)
{
    size_t start = 0;
    while (start < text.size() && (text[start] == ' ' || text[start] == '\t' || text[start] == '\r' || text[start] == '\n'))
        ++start;

    size_t end = text.size();
    while (end > start && (text[end - 1] == ' ' || text[end - 1] == '\t' || text[end - 1] == '\r' || text[end - 1] == '\n'))
        --end;

    return text.substr(start, end - start);
}

static bool ParseNumericToken(const std::string& token, int* outValue)
{
    if (!outValue || token.empty()) return false;
    std::string t = token;
    if (!t.empty() && t.back() == 'H')
        t.pop_back();
    int base = 10;
    if (t.rfind("0X", 0) == 0)
    {
        t = t.substr(2);
        base = 16;
    }
    else if (t.find_first_of("ABCDEF") != std::string::npos)
    {
        base = 16;
    }
    char* endPtr = nullptr;
    long v = strtol(t.c_str(), &endPtr, base);
    if (!endPtr || *endPtr != '\0')
        return false;
    *outValue = (int)v;
    return true;
}

static bool TryExtractBaseDisp(const std::string& asmUpper, const char* baseReg, int* outDisp)
{
    if (!outDisp) return false;
    std::string needle = std::string("[") + baseReg;
    size_t pos = asmUpper.find(needle);
    if (pos == std::string::npos)
        return false;

    size_t end = asmUpper.find(']', pos);
    if (end == std::string::npos)
        return false;

    std::string inner = asmUpper.substr(pos + 1, end - pos - 1);
    inner.erase(std::remove(inner.begin(), inner.end(), ' '), inner.end());
    if (inner.rfind(baseReg, 0) != 0)
        return false;

    if (inner.size() == strlen(baseReg))
    {
        *outDisp = 0;
        return true;
    }

    char sign = inner[strlen(baseReg)];
    std::string valueToken = inner.substr(strlen(baseReg) + 1);
    int value = 0;
    if ((sign != '+' && sign != '-') || !ParseNumericToken(valueToken, &value))
        return false;

    *outDisp = (sign == '-') ? -value : value;
    return true;
}

static int ScoreLikelyFailureText(const std::string& textUpper)
{
    const char* failWords[] = { "INVALID", "WRONG", "ERROR", "FAIL", "DENIED", "TRY AGAIN", "BAD", "NOPE" };
    int score = 0;
    for (const char* word : failWords)
    {
        if (textUpper.find(word) != std::string::npos)
            ++score;
    }
    return score;
}

static int ScoreLikelySuccessText(const std::string& textUpper)
{
    const char* okWords[] = { "SUCCESS", "CORRECT", "WELCOME", "VALID", "GOOD", "REGISTERED", "OK", "PASS" };
    int score = 0;
    for (const char* word : okWords)
    {
        if (textUpper.find(word) != std::string::npos)
            ++score;
    }
    return score;
}

static int ScoreAlgorithmFeatureText(const std::string& featureUpper)
{
    int score = 0;
    if (featureUpper.find("VALIDATION") != std::string::npos) score += 30;
    if (featureUpper.find("XOR LOOP") != std::string::npos) score += 35;
    if (featureUpper.find("CRC32") != std::string::npos) score += 28;
    if (featureUpper.find("BASE64") != std::string::npos) score += 24;
    return score;
}

static int AnalyzeFunctionAlgorithmScore(const FunctionAnalysisInfo& func, std::string* outReason)
{
    int startIndex = -1;
    int endIndex = -1;
    FunctionAnalysisInfo resolved = { 0 };
    if (!TryGetFunctionRangeForAddress(func.startAddr, &startIndex, &endIndex, &resolved))
    {
        if (outReason) *outReason = "function range unavailable";
        return -9999;
    }

    int cmpCount = 0;
    int testCount = 0;
    int jccCount = 0;
    int backwardJumpCount = 0;
    int arithmeticCount = 0;
    int callCount = 0;
    int stringCount = 0;
    int retCount = 0;
    int strongTextCount = 0;
    int instrCount = 0;

    for (int i = startIndex; i <= endIndex && i < startIndex + 220; ++i)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            continue;

        ++instrCount;
        const std::string asmUpper = ToUpperCopy(std::string(info.assembly));
        const std::string commentUpper = ToUpperCopy(info.comment);

        if (asmUpper.rfind("CMP", 0) == 0) ++cmpCount;
        if (asmUpper.rfind("TEST", 0) == 0) ++testCount;
        if (asmUpper.rfind("CALL", 0) == 0) ++callCount;
        if (asmUpper.rfind("RET", 0) == 0) ++retCount;

        const bool isJump = !asmUpper.empty() && asmUpper[0] == 'J';
        if (isJump && asmUpper.rfind("JMP", 0) != 0)
            ++jccCount;

        if (isJump)
        {
            size_t pos = asmUpper.find(' ');
            DWORD target = 0;
            if (pos != std::string::npos && TryParseHexAddress(asmUpper.substr(pos + 1), target) && target < info.address)
                ++backwardJumpCount;
        }

        if (asmUpper.rfind("XOR", 0) == 0 || asmUpper.rfind("ADD", 0) == 0 || asmUpper.rfind("SUB", 0) == 0 ||
            asmUpper.rfind("ADC", 0) == 0 || asmUpper.rfind("SBB", 0) == 0 || asmUpper.rfind("IMUL", 0) == 0 ||
            asmUpper.rfind("MUL", 0) == 0 || asmUpper.rfind("SHL", 0) == 0 || asmUpper.rfind("SHR", 0) == 0 ||
            asmUpper.rfind("SAR", 0) == 0 || asmUpper.rfind("ROL", 0) == 0 || asmUpper.rfind("ROR", 0) == 0 ||
            asmUpper.rfind("AND", 0) == 0 || asmUpper.rfind("OR", 0) == 0 || asmUpper.rfind("NOT", 0) == 0 ||
            asmUpper.rfind("NEG", 0) == 0 || asmUpper.rfind("LEA", 0) == 0 || asmUpper.rfind("INC", 0) == 0 ||
            asmUpper.rfind("DEC", 0) == 0)
        {
            ++arithmeticCount;
        }

        if (commentUpper.find("ASCII \"") != std::string::npos)
            ++stringCount;

        if (ScoreLikelyFailureText(commentUpper) > 0 || ScoreLikelySuccessText(commentUpper) > 0)
            ++strongTextCount;
    }

    int score = 0;
    score += ScoreAlgorithmFeatureText(ToUpperCopy(func.feature));
    score += (cmpCount + testCount > 6 ? 6 : (cmpCount + testCount)) * 4;
    score += (jccCount > 6 ? 6 : jccCount) * 3;
    score += (backwardJumpCount > 3 ? 3 : backwardJumpCount) * 7;
    score += (arithmeticCount > 10 ? 10 : arithmeticCount) * 3;
    score += (stringCount > 3 ? 3 : stringCount) * 3;
    score += (strongTextCount > 3 ? 3 : strongTextCount) * 5;

    if (instrCount >= 8 && instrCount <= 140) score += 6;
    if (callCount == 0) score += 4;
    if (callCount >= 3) score -= 6;
    if (instrCount < 6) score -= 20;
    if ((cmpCount + testCount) == 0 && arithmeticCount < 2 && callCount > 0) score -= 18;
    if (retCount > 2 && arithmeticCount < 2 && jccCount == 0) score -= 10;

    if (outReason)
    {
        char reason[512];
        sprintf_s(reason, sizeof(reason),
            "score=%d feature=%s cmp/test=%d jcc=%d loops=%d arithmetic=%d calls=%d strings=%d validation_text=%d",
            score, func.feature, cmpCount + testCount, jccCount, backwardJumpCount, arithmeticCount, callCount, stringCount, strongTextCount);
        *outReason = reason;
    }

    return score;
}

// ---------------------------------------------------------------------------
// Helper: safely write a JSON string to the output buffer
// ---------------------------------------------------------------------------
static bool SafeWriteResult(const std::string& json, char* outResult, int maxResultLen)
{
    if (!outResult || maxResultLen <= 0) return false;
    int len = (int)json.size();
    if (len >= maxResultLen) len = maxResultLen - 1;
    memcpy(outResult, json.c_str(), len);
    outResult[len] = '\0';
    return true;
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------
static std::string Tool_ReadAssembly(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    // --- Parse address argument ---
    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter. Expected hex string e.g. '0x001B1030'.";
        return result.dump();
    }

    std::string addrStr = args["address"].get<std::string>();
    DWORD addr = 0;
    if (!TryParseHexAddress(addrStr, addr))
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    int lines = 30;
    if (args.contains("lines") && args["lines"].is_number_integer())
    {
        lines = args["lines"].get<int>();
        if (lines < 5) lines = 5;
        if (lines > 120) lines = 120;
    }

    // --- Airspace defense: deny system-module addresses ---
    if (addr > 0x50000000)
    {
        result["success"] = true;
        result["content"] = "Access Denied: The address " + addrStr +
            " belongs to a system module or standard library. "
            "Do NOT analyze system APIs. Please infer its behavior "
            "from context and parameters, and return to analyzing the main logic.";
        return result.dump();
    }

    // --- Execute disassembly ---
    char disasmBuf[24576] = { 0 };
    int nLines = dbg_GetDisasmString(addr, lines, disasmBuf, sizeof(disasmBuf));

    result["success"] = true;
    result["content"] = std::string("Assembly code at address ") + addrStr + " (" + std::to_string(nLines) + " lines):\n" + disasmBuf;
    return result.dump();
}

static std::string Tool_ReadFunctionSummary(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter. Expected hex string e.g. '0x00401234'.";
        return result.dump();
    }

    std::string addrStr = args["address"].get<std::string>();
    DWORD addr = 0;
    if (!TryParseHexAddress(addrStr, addr))
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    FunctionAnalysisInfo func = { 0 };
    int startIndex = -1;
    int endIndex = -1;
    if (!TryGetFunctionRangeForAddress(addr, &startIndex, &endIndex, &func))
    {
        result["error"] = "No analyzed function contains address " + addrStr + ". Run AI function annotation first.";
        return result.dump();
    }

    std::string content;
    content += "Function summary\n";
    content += "Name: " + std::string(func.name) + "\n";
    char tmp[256];
    sprintf_s(tmp, sizeof(tmp), "Start: 0x%08X\nEnd: 0x%08X\n", func.startAddr, func.endAddr);
    content += tmp;
    content += "Signature: " + std::string(func.signature) + "\n";
    content += "Feature: " + std::string(func.feature) + "\n";

    std::vector<std::string> strings;
    std::vector<std::string> calls;
    for (int i = startIndex; i <= endIndex; ++i)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            continue;

        std::string asmStr = info.assembly;
        std::string cmtStr = info.comment;
        if (asmStr.rfind("CALL", 0) == 0 && calls.size() < 12)
        {
            calls.push_back(asmStr);
        }
        if (cmtStr.find("ASCII \"") != std::string::npos && strings.size() < 12)
        {
            strings.push_back(cmtStr);
        }
    }

    content += "\nInteresting strings inside this function:\n";
    if (strings.empty())
    {
        content += "  (none)\n";
    }
    else
    {
        for (const auto& s : strings)
            content += "  " + s + "\n";
    }

    content += "\nDirect calls inside this function:\n";
    if (calls.empty())
    {
        content += "  (none)\n";
    }
    else
    {
        for (const auto& c : calls)
            content += "  " + c + "\n";
    }

    content += "\nDisassembly of the current function:\n";
    for (int i = startIndex; i <= endIndex && i < startIndex + 180; ++i)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            continue;

        char line[768];
        sprintf_s(line, sizeof(line), "%s0x%08X: %-20s %s ; %s\n",
            (info.address == addr) ? ">> " : "   ",
            info.address, info.hexCode, info.assembly, info.comment);
        content += line;
    }

    result["success"] = true;
    result["content"] = content;
    result["function_name"] = func.name;
    result["start_address"] = func.startAddr;
    result["end_address"] = func.endAddr;
    result["feature"] = func.feature;
    return result.dump();
}

static std::string Tool_ReadValidationCheckpoints(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter.";
        return result.dump();
    }

    DWORD addr = 0;
    std::string addrStr = args["address"].get<std::string>();
    if (!TryParseHexAddress(addrStr, addr))
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    FunctionAnalysisInfo func = { 0 };
    int startIndex = -1;
    int endIndex = -1;
    if (!TryGetFunctionRangeForAddress(addr, &startIndex, &endIndex, &func))
    {
        result["error"] = "No analyzed function contains address " + addrStr + ".";
        return result.dump();
    }

    std::string content = "Validation checkpoints inside function " + std::string(func.name) + ":\n";
    nlohmann::json checkpoints = nlohmann::json::array();
    int found = 0;
    for (int i = startIndex; i <= endIndex && found < 16; ++i)
    {
        InstrInfo cmpInfo = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &cmpInfo))
            continue;

        std::string asmUpper = ToUpperCopy(cmpInfo.assembly);
        if (!(asmUpper.rfind("CMP", 0) == 0 || asmUpper.rfind("TEST", 0) == 0))
            continue;

        for (int j = i + 1; j <= endIndex && j <= i + 2; ++j)
        {
            InstrInfo jccInfo = { 0 };
            if (!dbg_GetGlobalDisasmItem(j, &jccInfo))
                continue;

            std::string jccUpper = ToUpperCopy(jccInfo.assembly);
            if (jccUpper.empty() || jccUpper[0] != 'J' || jccUpper.rfind("JMP", 0) == 0)
                continue;

            char line[1024];
            sprintf_s(line, sizeof(line),
                "  [Checkpoint %d]\n"
                "    Compare : 0x%08X  %s ; %s\n"
                "    Branch  : 0x%08X  %s ; %s\n",
                found + 1,
                cmpInfo.address, cmpInfo.assembly, cmpInfo.comment,
                jccInfo.address, jccInfo.assembly, jccInfo.comment);
            content += line;

            nlohmann::json item;
            item["compare_address"] = cmpInfo.address;
            item["compare_assembly"] = cmpInfo.assembly;
            item["compare_comment"] = cmpInfo.comment;
            item["branch_address"] = jccInfo.address;
            item["branch_assembly"] = jccInfo.assembly;
            item["branch_comment"] = jccInfo.comment;
            checkpoints.push_back(item);
            ++found;
            break;
        }
    }

    if (found == 0)
    {
        content += "  (none found)\n";
    }

    result["success"] = true;
    result["content"] = content;
    result["checkpoints"] = checkpoints;
    return result.dump();
}

static std::string Tool_ReadCalleeFunctions(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter.";
        return result.dump();
    }

    DWORD addr = 0;
    std::string addrStr = args["address"].get<std::string>();
    if (!TryParseHexAddress(addrStr, addr))
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    FunctionAnalysisInfo func = { 0 };
    int startIndex = -1;
    int endIndex = -1;
    if (!TryGetFunctionRangeForAddress(addr, &startIndex, &endIndex, &func))
    {
        result["error"] = "No analyzed function contains address " + addrStr + ".";
        return result.dump();
    }

    std::string content = "Direct callees from function " + std::string(func.name) + ":\n";
    nlohmann::json callees = nlohmann::json::array();
    std::vector<DWORD> seen;
    for (int i = startIndex; i <= endIndex && (int)callees.size() < 12; ++i)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            continue;

        std::string asmUpper = ToUpperCopy(info.assembly);
        if (asmUpper.rfind("CALL", 0) != 0)
            continue;

        DWORD target = 0;
        size_t pos = asmUpper.find(' ');
        if (pos == std::string::npos)
            continue;
        std::string targetPart = asmUpper.substr(pos + 1);
        if (!TryParseHexAddress(targetPart, target))
            continue;

        if (std::find(seen.begin(), seen.end(), target) != seen.end())
            continue;
        seen.push_back(target);

        FunctionAnalysisInfo callee = { 0 };
        if (FindContainingFunction(target, &callee))
        {
            char line[512];
            sprintf_s(line, sizeof(line), "  0x%08X -> %s [0x%08X - 0x%08X] feat=%s\n",
                info.address, callee.name, callee.startAddr, callee.endAddr, callee.feature);
            content += line;

            nlohmann::json item;
            item["callsite"] = info.address;
            item["target"] = callee.startAddr;
            item["name"] = callee.name;
            item["feature"] = callee.feature;
            callees.push_back(item);
        }
        else
        {
            char line[256];
            sprintf_s(line, sizeof(line), "  0x%08X -> 0x%08X (not an analyzed function)\n", info.address, target);
            content += line;
        }
    }

    if (callees.empty())
        content += "  (no analyzed direct callees)\n";

    result["success"] = true;
    result["content"] = content;
    result["callees"] = callees;
    return result.dump();
}

static std::string Tool_ReadBestAlgorithmCallee(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter.";
        return result.dump();
    }

    DWORD addr = 0;
    std::string addrStr = args["address"].get<std::string>();
    if (!TryParseHexAddress(addrStr, addr))
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    FunctionAnalysisInfo func = { 0 };
    int startIndex = -1;
    int endIndex = -1;
    if (!TryGetFunctionRangeForAddress(addr, &startIndex, &endIndex, &func))
    {
        result["error"] = "No analyzed function contains address " + addrStr + ".";
        return result.dump();
    }

    struct CandidateInfo
    {
        DWORD callsite;
        DWORD target;
        FunctionAnalysisInfo callee;
        int score;
        std::string reason;
    };

    std::vector<CandidateInfo> candidates;
    std::vector<DWORD> seenTargets;

    for (int i = startIndex; i <= endIndex && (int)candidates.size() < 16; ++i)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            continue;

        const std::string asmUpper = ToUpperCopy(std::string(info.assembly));
        if (asmUpper.rfind("CALL", 0) != 0)
            continue;

        size_t pos = asmUpper.find(' ');
        if (pos == std::string::npos)
            continue;

        DWORD target = 0;
        if (!TryParseHexAddress(asmUpper.substr(pos + 1), target))
            continue;

        if (std::find(seenTargets.begin(), seenTargets.end(), target) != seenTargets.end())
            continue;
        seenTargets.push_back(target);

        FunctionAnalysisInfo callee = { 0 };
        if (!EnsureFunctionAnalysisForAddress(target, &callee))
            continue;

        std::string reason;
        const int score = AnalyzeFunctionAlgorithmScore(callee, &reason);

        CandidateInfo item = {};
        item.callsite = info.address;
        item.target = callee.startAddr;
        item.callee = callee;
        item.score = score;
        item.reason = reason;
        candidates.push_back(item);
    }

    if (candidates.empty())
    {
        result["error"] = "No analyzed direct callees were found for this function.";
        return result.dump();
    }

    std::sort(candidates.begin(), candidates.end(), [](const CandidateInfo& a, const CandidateInfo& b) {
        return a.score > b.score;
    });

    const CandidateInfo& best = candidates.front();
    std::string content = "Most likely algorithm callee for function " + std::string(func.name) + ":\n";
    {
        char line[768];
        sprintf_s(line, sizeof(line),
            "Selected: %s [0x%08X - 0x%08X] score=%d called at 0x%08X\nFeature: %s\nReason: %s\n",
            best.callee.name, best.callee.startAddr, best.callee.endAddr, best.score, best.callsite,
            best.callee.feature, best.reason.c_str());
        content += line;
    }

    content += "\nRanked callee candidates:\n";
    nlohmann::json ranked = nlohmann::json::array();
    const size_t limit = candidates.size() < 5 ? candidates.size() : 5;
    for (size_t i = 0; i < limit; ++i)
    {
        const CandidateInfo& item = candidates[i];
        char line[768];
        sprintf_s(line, sizeof(line), "  %d. %s @ 0x%08X score=%d feat=%s\n     %s\n",
            (int)i + 1, item.callee.name, item.callee.startAddr, item.score, item.callee.feature, item.reason.c_str());
        content += line;

        nlohmann::json entry;
        entry["rank"] = (int)i + 1;
        entry["callsite"] = item.callsite;
        entry["target"] = item.callee.startAddr;
        entry["end"] = item.callee.endAddr;
        entry["name"] = item.callee.name;
        entry["feature"] = item.callee.feature;
        entry["score"] = item.score;
        entry["reason"] = item.reason;
        ranked.push_back(entry);
    }

    result["success"] = true;
    result["content"] = content;
    result["selected_target"] = best.callee.startAddr;
    result["selected_name"] = best.callee.name;
    result["selected_feature"] = best.callee.feature;
    result["selected_score"] = best.score;
    result["candidates"] = ranked;
    return result.dump();
}

static std::string Tool_ReadCallerFunctions(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter.";
        return result.dump();
    }

    DWORD addr = 0;
    std::string addrStr = args["address"].get<std::string>();
    if (!TryParseHexAddress(addrStr, addr))
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    FunctionAnalysisInfo func = { 0 };
    int startIndex = -1;
    int endIndex = -1;
    if (!TryGetFunctionRangeForAddress(addr, &startIndex, &endIndex, &func))
    {
        result["error"] = "No analyzed function contains address " + addrStr + ".";
        return result.dump();
    }

    const int total = dbg_GetGlobalDisasmCount();
    std::string content = "Direct callers of function " + std::string(func.name) + ":\n";
    nlohmann::json callers = nlohmann::json::array();
    std::vector<DWORD> seenCallerStarts;
    for (int i = 0; i < total && (int)callers.size() < 12; ++i)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            continue;

        std::string asmUpper = ToUpperCopy(info.assembly);
        if (asmUpper.rfind("CALL", 0) != 0)
            continue;

        DWORD target = 0;
        size_t pos = asmUpper.find(' ');
        if (pos == std::string::npos)
            continue;
        std::string targetPart = asmUpper.substr(pos + 1);
        if (!TryParseHexAddress(targetPart, target))
            continue;

        if (target != func.startAddr)
            continue;

        FunctionAnalysisInfo caller = { 0 };
        if (FindContainingFunction(info.address, &caller))
        {
            if (std::find(seenCallerStarts.begin(), seenCallerStarts.end(), caller.startAddr) != seenCallerStarts.end())
                continue;
            seenCallerStarts.push_back(caller.startAddr);

            char line[512];
            sprintf_s(line, sizeof(line), "  %s [0x%08X - 0x%08X] calls target at 0x%08X\n",
                caller.name, caller.startAddr, caller.endAddr, info.address);
            content += line;

            nlohmann::json item;
            item["callsite"] = info.address;
            item["caller_start"] = caller.startAddr;
            item["caller_name"] = caller.name;
            item["caller_feature"] = caller.feature;
            callers.push_back(item);
        }
        else
        {
            char line[256];
            sprintf_s(line, sizeof(line), "  0x%08X calls target function\n", info.address);
            content += line;
        }
    }

    if (callers.empty())
        content += "  (no analyzed direct callers)\n";

    result["success"] = true;
    result["content"] = content;
    result["callers"] = callers;
    return result.dump();
}

static std::string Tool_ReadFunctionInputs(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter.";
        return result.dump();
    }

    DWORD addr = 0;
    std::string addrStr = args["address"].get<std::string>();
    if (!TryParseHexAddress(addrStr, addr))
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    FunctionAnalysisInfo func = { 0 };
    int startIndex = -1;
    int endIndex = -1;
    if (!TryGetFunctionRangeForAddress(addr, &startIndex, &endIndex, &func))
    {
        result["error"] = "No analyzed function contains address " + addrStr + ".";
        return result.dump();
    }

    std::set<int> ebpPosOffsets;
    std::set<int> ebpNegOffsets;
    std::set<int> espOffsets;
    bool usesEarlyEcx = false;
    bool usesEarlyEdx = false;
    bool usesEarlyEsi = false;
    bool usesEarlyEdi = false;

    const int inspectEnd = (endIndex < (startIndex + 40)) ? endIndex : (startIndex + 40);
    for (int i = startIndex; i <= inspectEnd; ++i)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            continue;

        std::string asmUpper = ToUpperCopy(info.assembly);
        int disp = 0;
        if (TryExtractBaseDisp(asmUpper, "EBP", &disp))
        {
            if (disp > 4) ebpPosOffsets.insert(disp);
            else if (disp < 0) ebpNegOffsets.insert(-disp);
        }
        if (TryExtractBaseDisp(asmUpper, "ESP", &disp))
        {
            if (disp >= 0) espOffsets.insert(disp);
        }

        if (!usesEarlyEcx && asmUpper.find("ECX") != std::string::npos) usesEarlyEcx = true;
        if (!usesEarlyEdx && asmUpper.find("EDX") != std::string::npos) usesEarlyEdx = true;
        if (!usesEarlyEsi && asmUpper.find("ESI") != std::string::npos) usesEarlyEsi = true;
        if (!usesEarlyEdi && asmUpper.find("EDI") != std::string::npos) usesEarlyEdi = true;
    }

    std::string callConv = "unknown";
    if (usesEarlyEcx && usesEarlyEdx)
        callConv = "fastcall-like";
    else if (usesEarlyEcx)
        callConv = "thiscall/fastcall-like";
    else if (!ebpPosOffsets.empty())
        callConv = "stack-argument (cdecl/stdcall-like)";

    std::string content = "Recovered function input hints for " + std::string(func.name) + ":\n";
    content += "Likely calling convention: " + callConv + "\n";

    nlohmann::json stackArgs = nlohmann::json::array();
    content += "\nStack arguments inferred from [EBP+disp]:\n";
    if (ebpPosOffsets.empty())
    {
        content += "  (none)\n";
    }
    else
    {
        for (int disp : ebpPosOffsets)
        {
            int argIndex = (disp >= 8) ? ((disp - 8) / 4 + 1) : 0;
            char line[128];
            sprintf_s(line, sizeof(line), "  arg%d -> [EBP+0x%X]\n", argIndex, disp);
            content += line;

            nlohmann::json item;
            item["name"] = "arg" + std::to_string(argIndex);
            item["offset"] = disp;
            item["kind"] = "stack";
            stackArgs.push_back(item);
        }
    }

    nlohmann::json locals = nlohmann::json::array();
    content += "\nLocal stack variables inferred from [EBP-disp]/[ESP+disp]:\n";
    if (ebpNegOffsets.empty() && espOffsets.empty())
    {
        content += "  (none)\n";
    }
    else
    {
        for (int disp : ebpNegOffsets)
        {
            char line[128];
            sprintf_s(line, sizeof(line), "  local_0x%X -> [EBP-0x%X]\n", disp, disp);
            content += line;
            nlohmann::json item;
            item["name"] = "local_0x" + std::to_string(disp);
            item["offset"] = -disp;
            item["kind"] = "ebp_local";
            locals.push_back(item);
        }
        for (int disp : espOffsets)
        {
            char line[128];
            sprintf_s(line, sizeof(line), "  esp_slot_0x%X -> [ESP+0x%X]\n", disp, disp);
            content += line;
            nlohmann::json item;
            item["name"] = "esp_slot_0x" + std::to_string(disp);
            item["offset"] = disp;
            item["kind"] = "esp_slot";
            locals.push_back(item);
        }
    }

    nlohmann::json regHints = nlohmann::json::array();
    content += "\nEarly register usage hints:\n";
    if (!(usesEarlyEcx || usesEarlyEdx || usesEarlyEsi || usesEarlyEdi))
    {
        content += "  (none)\n";
    }
    else
    {
        if (usesEarlyEcx) { content += "  ECX used early in function\n"; regHints.push_back("ECX"); }
        if (usesEarlyEdx) { content += "  EDX used early in function\n"; regHints.push_back("EDX"); }
        if (usesEarlyEsi) { content += "  ESI used early in function\n"; regHints.push_back("ESI"); }
        if (usesEarlyEdi) { content += "  EDI used early in function\n"; regHints.push_back("EDI"); }
    }

    if (g_dwCurrentThreadId != 0)
    {
        RegInfo regs = { 0 };
        if (dbg_GetRegs(g_dwCurrentThreadId, &regs))
        {
            char line[256];
            sprintf_s(line, sizeof(line),
                "\nCurrent paused context:\n  EAX=%08X ECX=%08X EDX=%08X ESI=%08X EDI=%08X EBP=%08X ESP=%08X\n",
                regs.eax, regs.ecx, regs.edx, regs.esi, regs.edi, regs.ebp, regs.esp);
            content += line;
        }
    }

    result["success"] = true;
    result["content"] = content;
    result["calling_convention"] = callConv;
    result["stack_args"] = stackArgs;
    result["locals"] = locals;
    result["register_hints"] = regHints;
    return result.dump();
}

static std::string Tool_ReadValidationPaths(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter.";
        return result.dump();
    }

    DWORD addr = 0;
    std::string addrStr = args["address"].get<std::string>();
    if (!TryParseHexAddress(addrStr, addr))
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    FunctionAnalysisInfo func = { 0 };
    int startIndex = -1;
    int endIndex = -1;
    if (!TryGetFunctionRangeForAddress(addr, &startIndex, &endIndex, &func))
    {
        result["error"] = "No analyzed function contains address " + addrStr + ".";
        return result.dump();
    }

    std::string content = "Validation path summary for " + std::string(func.name) + ":\n";
    nlohmann::json paths = nlohmann::json::array();
    int found = 0;

    for (int i = startIndex; i <= endIndex && found < 8; ++i)
    {
        InstrInfo cmpInfo = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &cmpInfo))
            continue;

        std::string cmpUpper = ToUpperCopy(cmpInfo.assembly);
        if (!(cmpUpper.rfind("CMP", 0) == 0 || cmpUpper.rfind("TEST", 0) == 0))
            continue;

        InstrInfo jccInfo = { 0 };
        int jccIndex = -1;
        for (int j = i + 1; j <= endIndex && j <= i + 2; ++j)
        {
            if (!dbg_GetGlobalDisasmItem(j, &jccInfo))
                continue;
            std::string jccUpper = ToUpperCopy(jccInfo.assembly);
            if (!jccUpper.empty() && jccUpper[0] == 'J' && jccUpper.rfind("JMP", 0) != 0)
            {
                jccIndex = j;
                break;
            }
        }
        if (jccIndex == -1)
            continue;

        std::string jccUpper = ToUpperCopy(jccInfo.assembly);
        size_t pos = jccUpper.find(' ');
        DWORD targetAddr = 0;
        if (pos != std::string::npos)
            TryParseHexAddress(jccUpper.substr(pos + 1), targetAddr);

        int targetIndex = (targetAddr != 0) ? dbg_FindDisasmIndexByAddr(targetAddr) : -1;
        std::string branchPreview;
        std::string fallthroughPreview;
        int branchFailScore = 0, branchOkScore = 0, fallFailScore = 0, fallOkScore = 0;

        for (int k = 0; k < 3; ++k)
        {
            if (targetIndex != -1 && targetIndex + k <= endIndex)
            {
                InstrInfo info = { 0 };
                if (dbg_GetGlobalDisasmItem(targetIndex + k, &info))
                {
                    std::string cmt = info.comment;
                    if (!cmt.empty())
                    {
                        branchPreview += cmt + " | ";
                        std::string upper = ToUpperCopy(cmt);
                        branchFailScore += ScoreLikelyFailureText(upper);
                        branchOkScore += ScoreLikelySuccessText(upper);
                    }
                }
            }
            if (jccIndex + 1 + k <= endIndex)
            {
                InstrInfo info = { 0 };
                if (dbg_GetGlobalDisasmItem(jccIndex + 1 + k, &info))
                {
                    std::string cmt = info.comment;
                    if (!cmt.empty())
                    {
                        fallthroughPreview += cmt + " | ";
                        std::string upper = ToUpperCopy(cmt);
                        fallFailScore += ScoreLikelyFailureText(upper);
                        fallOkScore += ScoreLikelySuccessText(upper);
                    }
                }
            }
        }

        std::string branchGuess = "unknown";
        if (branchFailScore > branchOkScore) branchGuess = "likely failure";
        else if (branchOkScore > branchFailScore) branchGuess = "likely success";
        std::string fallthroughGuess = "unknown";
        if (fallFailScore > fallOkScore) fallthroughGuess = "likely failure";
        else if (fallOkScore > fallFailScore) fallthroughGuess = "likely success";

        char line[1400];
        sprintf_s(line, sizeof(line),
            "  [Path %d]\n"
            "    Check      : 0x%08X  %s\n"
            "    Branch     : 0x%08X  %s\n"
            "    Taken path : %s\n"
            "    Fallthrough: %s\n",
            found + 1,
            cmpInfo.address, cmpInfo.assembly,
            jccInfo.address, jccInfo.assembly,
            branchGuess.c_str(), fallthroughGuess.c_str());
        content += line;
        if (!branchPreview.empty()) content += "    Taken preview     : " + branchPreview + "\n";
        if (!fallthroughPreview.empty()) content += "    Fallthrough preview: " + fallthroughPreview + "\n";

        nlohmann::json item;
        item["compare_address"] = cmpInfo.address;
        item["branch_address"] = jccInfo.address;
        item["branch_guess"] = branchGuess;
        item["fallthrough_guess"] = fallthroughGuess;
        paths.push_back(item);
        ++found;
    }

    if (found == 0)
        content += "  (no path summary available)\n";

    result["success"] = true;
    result["content"] = content;
    result["paths"] = paths;
    return result.dump();
}

static std::string Tool_ReadRegisters(const nlohmann::json& args)
{
    nlohmann::json result;

    if (g_dwCurrentThreadId == 0)
    {
        result["success"] = false;
        result["error"] = "No current thread context. The process may not be paused at a debug breakpoint.";
        return result.dump();
    }

    RegInfo regs = { 0 };
    if (!dbg_GetRegs(g_dwCurrentThreadId, &regs))
    {
        result["success"] = false;
        result["error"] = "Failed to read registers from the debugger engine. The target thread may have exited.";
        return result.dump();
    }

    nlohmann::json regJson;
    regJson["EAX"] = regs.eax;
    regJson["EBX"] = regs.ebx;
    regJson["ECX"] = regs.ecx;
    regJson["EDX"] = regs.edx;
    regJson["ESI"] = regs.esi;
    regJson["EDI"] = regs.edi;
    regJson["EBP"] = regs.ebp;
    regJson["ESP"] = regs.esp;
    regJson["EIP"] = regs.eip;
    regJson["EFLAGS"] = regs.eflags;

    char buf[512];
    sprintf_s(buf, sizeof(buf),
        "Current register state:\n"
        "EAX=%08X  EBX=%08X  ECX=%08X  EDX=%08X\n"
        "ESI=%08X  EDI=%08X  EBP=%08X  ESP=%08X\n"
        "EIP=%08X  EFLAGS=%08X",
        regs.eax, regs.ebx, regs.ecx, regs.edx,
        regs.esi, regs.edi, regs.ebp, regs.esp,
        regs.eip, regs.eflags);

    result["success"] = true;
    result["content"] = buf;
    result["registers"] = regJson;
    return result.dump();
}

static std::string Tool_ReadMemoryHex(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter. Expected a hex string, e.g. '0x00401000'.";
        return result.dump();
    }

    std::string addrStr = args["address"].get<std::string>();
    DWORD addr = 0;
    if (addrStr.compare(0, 2, "0x") == 0 || addrStr.compare(0, 2, "0X") == 0)
        addr = (DWORD)strtoul(addrStr.c_str() + 2, nullptr, 16);
    else
        addr = (DWORD)strtoul(addrStr.c_str(), nullptr, 16);

    if (addr == 0)
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    int size = 64;
    if (args.contains("size") && args["size"].is_number())
    {
        size = args["size"].get<int>();
        if (size < 1) size = 1;
        if (size > 256) size = 256;
    }

    BYTE buffer[256] = { 0 };
    if (!dbg_ReadMemory(addr, buffer, size))
    {
        result["error"] = "Failed to read memory at address " + addrStr + ". The memory may be inaccessible or unmapped.";
        return result.dump();
    }

    std::string content = "Hex dump at " + addrStr + " (" + std::to_string(size) + " bytes):\n";
    char line[128];
    for (int i = 0; i < size; i += 16)
    {
        int offset = i;
        int remain = (16 < (size - i)) ? 16 : (size - i);

        int pos = sprintf_s(line, sizeof(line), "%08X: ", addr + offset);
        for (int j = 0; j < remain; j++)
            pos += sprintf_s(line + pos, sizeof(line) - pos, "%02X ", buffer[offset + j]);
        for (int j = remain; j < 16; j++)
            pos += sprintf_s(line + pos, sizeof(line) - pos, "   ");
        pos += sprintf_s(line + pos, sizeof(line) - pos, " ");
        for (int j = 0; j < remain; j++)
        {
            BYTE b = buffer[offset + j];
            pos += sprintf_s(line + pos, sizeof(line) - pos, "%c", (b >= 32 && b <= 126) ? b : '.');
        }
        content += line;
        content += "\n";
    }

    result["success"] = true;
    result["content"] = content;
    return result.dump();
}

static std::string Tool_ReadString(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter. Expected a hex string, e.g. '0x00402000'.";
        return result.dump();
    }

    DWORD addr = 0;
    const std::string addrStr = args["address"].get<std::string>();
    if (!TryParseHexAddress(addrStr, addr))
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    int length = 64;
    if (args.contains("length") && args["length"].is_number_integer())
    {
        length = args["length"].get<int>();
    }
    else if (args.contains("size") && args["size"].is_number_integer())
    {
        length = args["size"].get<int>();
    }
    if (length < 1) length = 1;
    if (length > 256) length = 256;

    BYTE buffer[256] = { 0 };
    if (!dbg_ReadMemory(addr, buffer, length))
    {
        result["error"] = "Failed to read memory at address " + addrStr + ".";
        return result.dump();
    }

    std::string escaped;
    int actualLen = 0;
    for (; actualLen < length; ++actualLen)
    {
        BYTE b = buffer[actualLen];
        if (b == 0)
            break;

        if (b == '\n') escaped += "\\n";
        else if (b == '\r') escaped += "\\r";
        else if (b == '\t') escaped += "\\t";
        else if (b == '\\') escaped += "\\\\";
        else if (b == '\"') escaped += "\\\"";
        else if (b >= 32 && b <= 126) escaped.push_back((char)b);
        else
        {
            char tmp[8];
            sprintf_s(tmp, sizeof(tmp), "\\x%02X", b);
            escaped += tmp;
        }
    }

    std::string content = "String at " + addrStr + ":\n";
    content += "  \"" + escaped + "\"\n";
    content += "  length=" + std::to_string(actualLen);
    if (actualLen < length && buffer[actualLen] == 0)
        content += " (null-terminated)";
    content += "\n";

    result["success"] = true;
    result["content"] = content;
    result["string"] = escaped;
    result["length"] = actualLen;
    return result.dump();
}

static std::string Tool_ReadImports(const nlohmann::json& args)
{
    nlohmann::json result;

    dbg_CollectImports();
    int count = dbg_GetImportCount();

    if (count == 0)
    {
        result["success"] = false;
        result["error"] = "No imports found. The target process may not be loaded yet.";
        return result.dump();
    }

    std::string content = "PE Import Table (" + std::to_string(count) + " functions):\n";
    content += "=== SENSITIVE APIs (recommended breakpoints) ===\n";

    nlohmann::json sensitiveList = nlohmann::json::array();
    for (int i = 0; i < count; i++)
    {
        ImportFuncInfo info;
        if (dbg_GetImportItem(i, &info) && info.isSensitive)
        {
            char line[512];
            sprintf_s(line, sizeof(line),
                "  %-20s ! %-30s @ IAT 0x%08X (resolved: 0x%08X)",
                info.dllName, info.funcName, info.iatAddr, info.funcAddr);
            content += line;
            content += "\n";

            nlohmann::json item;
            item["dll"] = info.dllName;
            item["function"] = info.funcName;
            item["iat_address"] = info.iatAddr;
            item["resolved_address"] = info.funcAddr;
            sensitiveList.push_back(item);
        }
    }

    content += "\n=== Other imports ===\n";
    int otherCount = 0;
    for (int i = 0; i < count; i++)
    {
        ImportFuncInfo info;
        if (dbg_GetImportItem(i, &info) && !info.isSensitive)
        {
            otherCount++;
            if (otherCount <= 30)
            {
                char line[512];
                sprintf_s(line, sizeof(line),
                    "  %-20s   %-30s @ IAT 0x%08X",
                    info.dllName, info.funcName, info.iatAddr);
                content += line;
                content += "\n";
            }
        }
    }
    if (otherCount > 30)
        content += "  ... and " + std::to_string(otherCount - 30) + " more non-sensitive imports\n";

    result["success"] = true;
    result["content"] = content;
    result["sensitive_apis"] = sensitiveList;
    result["total_imports"] = count;
    return result.dump();
}

static std::string Tool_FindStringRefs(const nlohmann::json& args)
{
    nlohmann::json result;

    dbg_CollectStringRefs();
    int count = dbg_GetStringRefCount();

    if (count == 0)
    {
        result["success"] = false;
        result["error"] = "No interesting string references found in the disassembly.";
        return result.dump();
    }

    std::string content = "Interesting String Cross-References (" + std::to_string(count) + " found):\n";

    nlohmann::json refList = nlohmann::json::array();
    for (int i = 0; i < count; i++)
    {
        StringRefInfo info;
        if (dbg_GetStringRefItem(i, &info))
        {
            char line[512];
            sprintf_s(line, sizeof(line),
                "  RefAddr: 0x%08X  StringAddr: 0x%08X  Asm: %s  String: \"%s\"",
                info.refAddr, info.stringAddr, info.refAsm, info.stringValue);
            content += line;
            content += "\n";

            nlohmann::json item;
            item["ref_address"] = info.refAddr;
            item["string_address"] = info.stringAddr;
            item["string_value"] = info.stringValue;
            item["assembly"] = info.refAsm;
            refList.push_back(item);
        }
    }

    result["success"] = true;
    result["content"] = content;
    result["references"] = refList;
    return result.dump();
}

static std::string Tool_GetCallParameters(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter. Expected hex string e.g. '0x00401234'.";
        return result.dump();
    }

    std::string addrStr = args["address"].get<std::string>();
    DWORD callAddr = 0;
    if (!TryParseHexAddress(addrStr, callAddr))
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    dbg_EnsureDisasm(callAddr);
    int callIndex = dbg_FindDisasmIndexByAddr(callAddr);
    if (callIndex == -1)
    {
        result["error"] = "CALL instruction not found at address " + addrStr;
        return result.dump();
    }

    InstrInfo callInfo = { 0 };
    if (!dbg_GetGlobalDisasmItem(callIndex, &callInfo))
    {
        result["error"] = "Failed to read CALL instruction at " + addrStr;
        return result.dump();
    }

    const std::string callAsmUpper = ToUpperCopy(std::string(callInfo.assembly));
    if (callAsmUpper.rfind("CALL", 0) != 0)
    {
        result["error"] = "Instruction at " + addrStr + " is not a CALL instruction";
        return result.dump();
    }

    std::vector<std::string> parameters;
    int stackCleanupBytes = 0;
    std::string callingConvention = "unknown";
    bool isIndirectCall = (callAsmUpper.find("CALL [") != std::string::npos || 
                          callAsmUpper.find("CALL DWORD PTR") != std::string::npos);

    int searchStart = (callIndex - 30) > 0 ? (callIndex - 30) : 0;
    int pushCount = 0;

    for (int i = callIndex - 1; i >= searchStart; --i)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            break;

        const std::string asmUpper = ToUpperCopy(std::string(info.assembly));
        
        if (asmUpper.rfind("PUSH", 0) == 0)
        {
            parameters.insert(parameters.begin(), std::string(info.assembly));
            pushCount++;
        }
        else if (asmUpper.rfind("CALL", 0) == 0 || 
                 asmUpper.rfind("RET", 0) == 0 ||
                 asmUpper.rfind("JMP", 0) == 0 ||
                 (asmUpper.size() > 0 && asmUpper[0] == 'J' && asmUpper.rfind("JMP", 0) != 0))
        {
            break;
        }
    }

    int totalCount = dbg_GetGlobalDisasmCount();
    int searchEnd = (callIndex + 10) < (totalCount - 1) ? (callIndex + 10) : (totalCount - 1);
    for (int i = callIndex + 1; i <= searchEnd; ++i)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            break;

        const std::string asmUpper = ToUpperCopy(std::string(info.assembly));
        
        if (asmUpper.rfind("ADD ESP,", 0) == 0)
        {
            size_t commaPos = asmUpper.find(',');
            if (commaPos != std::string::npos)
            {
                std::string valueStr = asmUpper.substr(commaPos + 1);
                int value = 0;
                if (ParseNumericToken(TrimAscii(valueStr), &value))
                {
                    stackCleanupBytes = value;
                    if (stackCleanupBytes > 0 && pushCount > 0)
                    {
                        if (stackCleanupBytes == pushCount * 4)
                        {
                            callingConvention = "cdecl (caller cleans up)";
                        }
                    }
                    break;
                }
            }
        }
        else if (asmUpper.rfind("RET", 0) == 0)
        {
            size_t spacePos = asmUpper.find(' ');
            if (spacePos != std::string::npos)
            {
                std::string valueStr = asmUpper.substr(spacePos + 1);
                int value = 0;
                if (ParseNumericToken(TrimAscii(valueStr), &value))
                {
                    stackCleanupBytes = value;
                    if (stackCleanupBytes > 0 && pushCount > 0)
                    {
                        if (stackCleanupBytes == pushCount * 4)
                        {
                            callingConvention = "stdcall (callee cleans up)";
                        }
                    }
                }
            }
            break;
        }
        else if (asmUpper.rfind("LEAVE", 0) == 0)
        {
            callingConvention = "stdcall-like (uses LEAVE)";
        }
        else if (asmUpper.rfind("CALL", 0) == 0 ||
                 asmUpper.rfind("JMP", 0) == 0 ||
                 (asmUpper.size() > 0 && asmUpper[0] == 'J' && asmUpper.rfind("JMP", 0) != 0))
        {
            break;
        }
    }

    if (callingConvention == "unknown" && pushCount > 0)
    {
        callingConvention = "unknown (no explicit stack cleanup found)";
    }

    std::string content = "CALL instruction analysis at " + addrStr + ":\n";
    content += "  CALL instruction: " + std::string(callInfo.assembly) + "\n";
    if (isIndirectCall)
    {
        content += "  NOTE: This is an indirect call (function pointer)\n";
    }
    content += "  Calling convention: " + callingConvention + "\n";
    content += "  Stack cleanup bytes: " + std::to_string(stackCleanupBytes) + "\n";
    content += "  Parameters (pushed right-to-left, shown left-to-right):\n";
    
    if (parameters.empty())
    {
        content += "    (no PUSH instructions found before CALL)\n";
    }
    else
    {
        for (size_t i = 0; i < parameters.size(); ++i)
        {
            char line[128];
            sprintf_s(line, sizeof(line), "    arg%d: %s\n", (int)i + 1, parameters[i].c_str());
            content += line;
        }
    }

    result["success"] = true;
    result["content"] = content;
    result["call_address"] = callAddr;
    result["call_instruction"] = std::string(callInfo.assembly);
    result["calling_convention"] = callingConvention;
    result["stack_cleanup_bytes"] = stackCleanupBytes;
    result["parameters"] = parameters;
    result["is_indirect_call"] = isIndirectCall;
    return result.dump();
}

static std::string Tool_FindKeyComparison(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    DWORD startAddr = 0;
    int searchRange = 500;

    if (args.contains("address") && args["address"].is_string())
    {
        std::string addrStr = args["address"].get<std::string>();
        if (!TryParseHexAddress(addrStr, startAddr))
        {
            result["error"] = "Failed to parse address: " + addrStr;
            return result.dump();
        }
    }

    if (args.contains("range") && args["range"].is_number())
    {
        searchRange = args["range"].get<int>();
        if (searchRange < 50) searchRange = 50;
        if (searchRange > 2000) searchRange = 2000;
    }

    dbg_EnsureDisasm(startAddr);
    
    int startIndex = 0;
    int endIndex = 0;
    
    if (startAddr != 0)
    {
        int centerIndex = dbg_FindDisasmIndexByAddr(startAddr);
        if (centerIndex != -1)
        {
            int total = dbg_GetGlobalDisasmCount();
            startIndex = (centerIndex - searchRange / 2) > 0 ? (centerIndex - searchRange / 2) : 0;
            endIndex = (centerIndex + searchRange / 2) < (total - 1) ? (centerIndex + searchRange / 2) : (total - 1);
        }
    }
    
    if (startIndex == 0 && endIndex == 0)
    {
        startIndex = 0;
        int total = dbg_GetGlobalDisasmCount();
        endIndex = searchRange < (total - 1) ? searchRange : (total - 1);
    }

    struct ComparisonPoint
    {
        DWORD address;
        std::string assembly;
        std::string comment;
        std::string type;
        std::string branchAssembly;
        DWORD branchAddress;
    };

    std::vector<ComparisonPoint> comparisons;

    for (int i = startIndex; i <= endIndex; ++i)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            continue;

        const std::string asmUpper = ToUpperCopy(std::string(info.assembly));
        
        bool isKeyComparison = false;
        std::string comparisonType;

        if (asmUpper.rfind("CMP", 0) == 0)
        {
            isKeyComparison = true;
            comparisonType = "CMP";
        }
        else if (asmUpper.rfind("TEST", 0) == 0)
        {
            isKeyComparison = true;
            comparisonType = "TEST";
        }
        else if (asmUpper.rfind("REPE", 0) == 0 || asmUpper.rfind("REPNE", 0) == 0)
        {
            isKeyComparison = true;
            comparisonType = "STRING_COMPARE";
        }

        if (isKeyComparison)
        {
            ComparisonPoint point;
            point.address = info.address;
            point.assembly = std::string(info.assembly);
            point.comment = std::string(info.comment);
            point.type = comparisonType;
            point.branchAddress = 0;
            point.branchAssembly = "";

            int branchEnd = (i + 3) < endIndex ? (i + 3) : endIndex;
            for (int j = i + 1; j <= branchEnd; ++j)
            {
                InstrInfo jccInfo = { 0 };
                if (!dbg_GetGlobalDisasmItem(j, &jccInfo))
                    break;

                const std::string jccAsmUpper = ToUpperCopy(std::string(jccInfo.assembly));
                if (!jccAsmUpper.empty() && jccAsmUpper[0] == 'J' && jccAsmUpper.rfind("JMP", 0) != 0)
                {
                    point.branchAddress = jccInfo.address;
                    point.branchAssembly = std::string(jccInfo.assembly);
                    break;
                }
            }

            comparisons.push_back(point);
        }
    }

    std::string content = "Key comparison points found:\n";
    nlohmann::json foundComparisons = nlohmann::json::array();

    if (comparisons.empty())
    {
        content += "  (no key comparison points found in the specified range)\n";
    }
    else
    {
        for (size_t i = 0; i < comparisons.size(); ++i)
        {
            const auto& cmp = comparisons[i];
            char line[1024];
            
            if (cmp.branchAddress != 0)
            {
                sprintf_s(line, sizeof(line),
                    "  [%d] 0x%08X: %-20s ; %s\n"
                    "       Branch: 0x%08X: %s\n",
                    (int)i + 1, cmp.address, cmp.assembly.c_str(), cmp.comment.c_str(),
                    cmp.branchAddress, cmp.branchAssembly.c_str());
            }
            else
            {
                sprintf_s(line, sizeof(line),
                    "  [%d] 0x%08X: %-20s ; %s\n"
                    "       (no conditional branch found immediately after)\n",
                    (int)i + 1, cmp.address, cmp.assembly.c_str(), cmp.comment.c_str());
            }
            
            content += line;

            nlohmann::json item;
            item["address"] = cmp.address;
            item["assembly"] = cmp.assembly;
            item["comment"] = cmp.comment;
            item["type"] = cmp.type;
            item["branch_address"] = cmp.branchAddress;
            item["branch_assembly"] = cmp.branchAssembly;
            foundComparisons.push_back(item);
        }
    }

    result["success"] = true;
    result["content"] = content;
    result["comparisons"] = foundComparisons;
    result["search_start_index"] = startIndex;
    result["search_end_index"] = endIndex;
    return result.dump();
}

static std::string Tool_TraceDataFlow(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter. Expected hex string e.g. '0x00401234'.";
        return result.dump();
    }

    std::string addrStr = args["address"].get<std::string>();
    DWORD startAddr = 0;
    if (!TryParseHexAddress(addrStr, startAddr))
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    int traceDepth = 50;
    if (args.contains("depth") && args["depth"].is_number())
    {
        traceDepth = args["depth"].get<int>();
        if (traceDepth < 10) traceDepth = 10;
        if (traceDepth > 200) traceDepth = 200;
    }

    dbg_EnsureDisasm(startAddr);
    int startIndex = dbg_FindDisasmIndexByAddr(startAddr);
    if (startIndex == -1)
    {
        result["error"] = "Instruction not found at address " + addrStr;
        return result.dump();
    }

    int totalCount = dbg_GetGlobalDisasmCount();
    int endIndex = (startIndex + traceDepth) < (totalCount - 1) ? (startIndex + traceDepth) : (totalCount - 1);

    struct DataFlowStep
    {
        DWORD address;
        std::string assembly;
        std::string comment;
        std::string operation;
        std::string destReg;
        std::string srcReg;
        bool isMemoryAccess;
        bool isArithmetic;
    };

    std::vector<DataFlowStep> flowSteps;
    std::set<std::string> trackedRegs;

    InstrInfo startInfo = { 0 };
    if (dbg_GetGlobalDisasmItem(startIndex, &startInfo))
    {
        const std::string asmUpper = ToUpperCopy(std::string(startInfo.assembly));
        
        if (asmUpper.find("EAX") != std::string::npos) trackedRegs.insert("EAX");
        if (asmUpper.find("EBX") != std::string::npos) trackedRegs.insert("EBX");
        if (asmUpper.find("ECX") != std::string::npos) trackedRegs.insert("ECX");
        if (asmUpper.find("EDX") != std::string::npos) trackedRegs.insert("EDX");
        if (asmUpper.find("ESI") != std::string::npos) trackedRegs.insert("ESI");
        if (asmUpper.find("EDI") != std::string::npos) trackedRegs.insert("EDI");
    }

    if (trackedRegs.empty())
    {
        trackedRegs.insert("EAX");
        trackedRegs.insert("EBX");
        trackedRegs.insert("ECX");
        trackedRegs.insert("EDX");
    }

    for (int i = startIndex; i <= endIndex; ++i)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            break;

        const std::string asmUpper = ToUpperCopy(std::string(info.assembly));
        
        DataFlowStep step;
        step.address = info.address;
        step.assembly = std::string(info.assembly);
        step.comment = std::string(info.comment);
        step.operation = "";
        step.destReg = "";
        step.srcReg = "";
        step.isMemoryAccess = (asmUpper.find("[") != std::string::npos);
        step.isArithmetic = false;

        bool isRelevant = false;

        for (const auto& reg : trackedRegs)
        {
            if (asmUpper.find(reg) != std::string::npos)
            {
                isRelevant = true;
                break;
            }
        }

        if (asmUpper.rfind("MOV", 0) == 0)
        {
            step.operation = "MOV";
            size_t commaPos = asmUpper.find(',');
            if (commaPos != std::string::npos)
            {
                step.destReg = TrimAscii(asmUpper.substr(3, commaPos - 3));
                step.srcReg = TrimAscii(asmUpper.substr(commaPos + 1));
            }
        }
        else if (asmUpper.rfind("ADD", 0) == 0 || asmUpper.rfind("SUB", 0) == 0 ||
                 asmUpper.rfind("XOR", 0) == 0 || asmUpper.rfind("AND", 0) == 0 ||
                 asmUpper.rfind("OR", 0) == 0 || asmUpper.rfind("SHL", 0) == 0 ||
                 asmUpper.rfind("SHR", 0) == 0 || asmUpper.rfind("ROL", 0) == 0 ||
                 asmUpper.rfind("ROR", 0) == 0 || asmUpper.rfind("IMUL", 0) == 0 ||
                 asmUpper.rfind("MUL", 0) == 0 || asmUpper.rfind("INC", 0) == 0 ||
                 asmUpper.rfind("DEC", 0) == 0 || asmUpper.rfind("NEG", 0) == 0 ||
                 asmUpper.rfind("NOT", 0) == 0)
        {
            step.isArithmetic = true;
            size_t spacePos = asmUpper.find(' ');
            if (spacePos != std::string::npos)
            {
                step.operation = asmUpper.substr(0, spacePos);
            }
            else
            {
                step.operation = asmUpper;
            }
        }
        else if (asmUpper.rfind("PUSH", 0) == 0)
        {
            step.operation = "PUSH";
        }
        else if (asmUpper.rfind("POP", 0) == 0)
        {
            step.operation = "POP";
        }
        else if (asmUpper.rfind("LEA", 0) == 0)
        {
            step.operation = "LEA";
        }
        else if (asmUpper.rfind("CMP", 0) == 0 || asmUpper.rfind("TEST", 0) == 0)
        {
            step.operation = asmUpper.substr(0, 3);
        }
        else if (!asmUpper.empty() && asmUpper[0] == 'J')
        {
            step.operation = "JUMP";
        }
        else if (asmUpper.rfind("CALL", 0) == 0)
        {
            step.operation = "CALL";
        }
        else if (asmUpper.rfind("RET", 0) == 0)
        {
            step.operation = "RET";
            break;
        }

        if (isRelevant || step.isArithmetic || step.operation == "CMP" || step.operation == "TEST")
        {
            flowSteps.push_back(step);

            if (!step.destReg.empty())
            {
                trackedRegs.insert(step.destReg);
            }
        }
    }

    std::string content = "Data flow trace starting at " + addrStr + ":\n";
    nlohmann::json flowStepsJson = nlohmann::json::array();

    if (flowSteps.empty())
    {
        content += "  (no relevant data flow operations found in the trace range)\n";
    }
    else
    {
        for (size_t i = 0; i < flowSteps.size(); ++i)
        {
            const auto& step = flowSteps[i];
            char line[1024];
            
            std::string flags;
            if (step.isArithmetic) flags += " [ARITHMETIC]";
            if (step.isMemoryAccess) flags += " [MEM]";
            
            sprintf_s(line, sizeof(line),
                "  [%02d] 0x%08X: %-20s ; %s%s\n",
                (int)i + 1, step.address, step.assembly.c_str(), 
                step.comment.c_str(), flags.c_str());
            
            content += line;

            nlohmann::json item;
            item["address"] = step.address;
            item["assembly"] = step.assembly;
            item["comment"] = step.comment;
            item["operation"] = step.operation;
            item["dest_reg"] = step.destReg;
            item["src_reg"] = step.srcReg;
            item["is_memory_access"] = step.isMemoryAccess;
            item["is_arithmetic"] = step.isArithmetic;
            flowStepsJson.push_back(item);
        }
    }

    result["success"] = true;
    result["content"] = content;
    result["flow_steps"] = flowStepsJson;
    result["start_address"] = startAddr;
    result["trace_depth"] = traceDepth;
    return result.dump();
}

static std::string Tool_AnalyzeStringDecryption(const nlohmann::json& args)
{
    nlohmann::json result;
    result["success"] = false;

    if (!args.contains("address") || !args["address"].is_string())
    {
        result["error"] = "Missing or invalid 'address' parameter. Expected hex string e.g. '0x00401234'.";
        return result.dump();
    }

    std::string addrStr = args["address"].get<std::string>();
    DWORD startAddr = 0;
    if (!TryParseHexAddress(addrStr, startAddr))
    {
        result["error"] = "Failed to parse address: " + addrStr;
        return result.dump();
    }

    int analysisRange = 100;
    if (args.contains("range") && args["range"].is_number())
    {
        analysisRange = args["range"].get<int>();
        if (analysisRange < 20) analysisRange = 20;
        if (analysisRange > 500) analysisRange = 500;
    }

    dbg_EnsureDisasm(startAddr);
    int startIndex = dbg_FindDisasmIndexByAddr(startAddr);
    if (startIndex == -1)
    {
        result["error"] = "Instruction not found at address " + addrStr;
        return result.dump();
    }

    int totalCount = dbg_GetGlobalDisasmCount();
    int endIndex = (startIndex + analysisRange) < (totalCount - 1) ? (startIndex + analysisRange) : (totalCount - 1);

    struct DecryptionPattern
    {
        DWORD startAddress;
        DWORD endAddress;
        std::string patternType;
        std::string description;
        std::vector<std::string> keyInstructions;
        std::string sourceRegister;
        std::string destRegister;
        std::string keyRegister;
    };

    std::vector<DecryptionPattern> patterns;

    for (int i = startIndex; i <= endIndex; ++i)
    {
        InstrInfo info = { 0 };
        if (!dbg_GetGlobalDisasmItem(i, &info))
            break;

        const std::string asmUpper = ToUpperCopy(std::string(info.assembly));
        const std::string comment = std::string(info.comment);
        
        bool isStringDecryption = false;
        DecryptionPattern pattern;
        pattern.startAddress = info.address;
        pattern.patternType = "unknown";
        pattern.description = "";

        if (asmUpper.find("XOR") != std::string::npos && 
            (asmUpper.find("[") != std::string::npos || comment.find("ASCII") != std::string::npos))
        {
            pattern.patternType = "XOR_DECRYPT";
            pattern.description = "XOR decryption loop detected";
            isStringDecryption = true;
        }
        else if (asmUpper.find("ADD") != std::string::npos && 
                 (asmUpper.find("[") != std::string::npos || comment.find("ASCII") != std::string::npos))
        {
            pattern.patternType = "ADD_DECRYPT";
            pattern.description = "Addition-based decryption detected";
            isStringDecryption = true;
        }
        else if (asmUpper.find("SUB") != std::string::npos && 
                 (asmUpper.find("[") != std::string::npos || comment.find("ASCII") != std::string::npos))
        {
            pattern.patternType = "SUB_DECRYPT";
            pattern.description = "Subtraction-based decryption detected";
            isStringDecryption = true;
        }
        else if (asmUpper.rfind("MOVSB", 0) == 0 || asmUpper.rfind("MOVSW", 0) == 0 || 
                 asmUpper.rfind("MOVSD", 0) == 0)
        {
            pattern.patternType = "STRING_MOVE";
            pattern.description = "String move operation (REP MOVSx)";
            isStringDecryption = true;
        }
        else if (asmUpper.rfind("STOSB", 0) == 0 || asmUpper.rfind("STOSW", 0) == 0 || 
                 asmUpper.rfind("STOSD", 0) == 0)
        {
            pattern.patternType = "STRING_STORE";
            pattern.description = "String store operation (STOSx)";
            isStringDecryption = true;
        }
        else if (asmUpper.rfind("LODSB", 0) == 0 || asmUpper.rfind("LODSW", 0) == 0 || 
                 asmUpper.rfind("LODSD", 0) == 0)
        {
            pattern.patternType = "STRING_LOAD";
            pattern.description = "String load operation (LODSx)";
            isStringDecryption = true;
        }
        else if (asmUpper.rfind("REPE", 0) == 0 || asmUpper.rfind("REPNE", 0) == 0)
        {
            pattern.patternType = "STRING_COMPARE";
            pattern.description = "String compare operation (REPE/REPNE CMPSx/SCASx)";
            isStringDecryption = true;
        }

        if (isStringDecryption)
        {
            pattern.keyInstructions.push_back(std::string(info.assembly));
            
            for (int j = i - 10; j <= i + 20 && j <= endIndex; ++j)
            {
                if (j < 0) continue;
                if (j == i) continue;
                
                InstrInfo surroundingInfo = { 0 };
                if (!dbg_GetGlobalDisasmItem(j, &surroundingInfo))
                    continue;
                
                const std::string surroundingAsm = ToUpperCopy(std::string(surroundingInfo.assembly));
                
                if (surroundingAsm.find("ECX") != std::string::npos || surroundingAsm.find("CX") != std::string::npos)
                {
                    if (surroundingAsm.rfind("MOV", 0) == 0 || surroundingAsm.rfind("XOR", 0) == 0)
                    {
                        pattern.keyInstructions.push_back(std::string(surroundingInfo.assembly));
                    }
                }
                if (surroundingAsm.find("ESI") != std::string::npos || surroundingAsm.find("SI") != std::string::npos)
                {
                    if (surroundingAsm.rfind("MOV", 0) == 0 || surroundingAsm.rfind("LEA", 0) == 0)
                    {
                        pattern.keyInstructions.push_back(std::string(surroundingInfo.assembly));
                    }
                }
                if (surroundingAsm.find("EDI") != std::string::npos || surroundingAsm.find("DI") != std::string::npos)
                {
                    if (surroundingAsm.rfind("MOV", 0) == 0 || surroundingAsm.rfind("LEA", 0) == 0)
                    {
                        pattern.keyInstructions.push_back(std::string(surroundingInfo.assembly));
                    }
                }
                if (surroundingAsm.find("AL") != std::string::npos || surroundingAsm.find("AH") != std::string::npos ||
                    surroundingAsm.find("AX") != std::string::npos || surroundingAsm.find("EAX") != std::string::npos)
                {
                    if (surroundingAsm.rfind("MOV", 0) == 0 || surroundingAsm.rfind("XOR", 0) == 0)
                    {
                        pattern.keyInstructions.push_back(std::string(surroundingInfo.assembly));
                    }
                }
            }

            pattern.endAddress = info.address;
            patterns.push_back(pattern);
        }
    }

    std::string content = "String decryption/processing analysis starting at " + addrStr + ":\n";
    nlohmann::json patternsJson = nlohmann::json::array();

    if (patterns.empty())
    {
        content += "  (no obvious string decryption/processing patterns found in the range)\n";
    }
    else
    {
        for (size_t i = 0; i < patterns.size(); ++i)
        {
            const auto& pattern = patterns[i];
            char line[1024];
            
            sprintf_s(line, sizeof(line),
                "  [Pattern %d] Type: %s\n"
                "    Address range: 0x%08X - 0x%08X\n"
                "    Description: %s\n",
                (int)i + 1, pattern.patternType.c_str(),
                pattern.startAddress, pattern.endAddress,
                pattern.description.c_str());
            
            content += line;
            
            content += "    Key instructions:\n";
            for (size_t j = 0; j < pattern.keyInstructions.size() && j < 10; ++j)
            {
                char instrLine[256];
                sprintf_s(instrLine, sizeof(instrLine), "      %s\n", pattern.keyInstructions[j].c_str());
                content += instrLine;
            }
            if (pattern.keyInstructions.size() > 10)
            {
                content += "      ... and more\n";
            }
            content += "\n";

            nlohmann::json item;
            item["type"] = pattern.patternType;
            item["start_address"] = pattern.startAddress;
            item["end_address"] = pattern.endAddress;
            item["description"] = pattern.description;
            item["key_instructions"] = pattern.keyInstructions;
            patternsJson.push_back(item);
        }
    }

    result["success"] = true;
    result["content"] = content;
    result["patterns"] = patternsJson;
    result["start_address"] = startAddr;
    result["analysis_range"] = analysisRange;
    return result.dump();
}

// ---------------------------------------------------------------------------
// Dispatcher registry
// ---------------------------------------------------------------------------
using ToolHandler = std::function<std::string(const nlohmann::json&)>;

static std::map<std::string, ToolHandler> g_ToolRegistry = {
    { "read_assembly", Tool_ReadAssembly },
    { "read_function_summary", Tool_ReadFunctionSummary },
    { "read_validation_checkpoints", Tool_ReadValidationCheckpoints },
    { "read_function_inputs", Tool_ReadFunctionInputs },
    { "read_validation_paths", Tool_ReadValidationPaths },
    { "read_callee_functions", Tool_ReadCalleeFunctions },
    { "read_best_algorithm_callee", Tool_ReadBestAlgorithmCallee },
    { "read_caller_functions", Tool_ReadCallerFunctions },
    { "read_registers", Tool_ReadRegisters },
    { "read_memory_hex", Tool_ReadMemoryHex },
    { "read_string", Tool_ReadString },
    { "read_imports", Tool_ReadImports },
    { "find_string_refs", Tool_FindStringRefs },
    { "get_call_parameters", Tool_GetCallParameters },
    { "find_key_comparison", Tool_FindKeyComparison },
    { "trace_data_flow", Tool_TraceDataFlow },
    { "analyze_string_decryption", Tool_AnalyzeStringDecryption }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
AITOOLS_API bool InitAITools(HANDLE hProcess, DWORD pid)
{
    try
    {
        g_hProcess = hProcess;
        g_dwPid    = pid;
        return true;
    }
    catch (...)
    {
        return false;
    }
}

AITOOLS_API void SetCurrentThreadId(DWORD threadId)
{
    g_dwCurrentThreadId = threadId;
}

AITOOLS_API int ExecuteAITool(const char* toolName, const char* jsonArgs, char* outResult, int maxResultLen)
{
    if (!toolName || !jsonArgs || !outResult || maxResultLen <= 0)
        return 0;

    try
    {
        // --- Parse incoming JSON arguments ---
        nlohmann::json args;
        try
        {
            args = nlohmann::json::parse(jsonArgs);
        }
        catch (const std::exception& e)
        {
            nlohmann::json err;
            err["success"] = false;
            err["error"] = std::string("JSON parse error: ") + e.what();
            SafeWriteResult(err.dump(), outResult, maxResultLen);
            return 0;
        }

        // --- Dispatch ---
        auto it = g_ToolRegistry.find(toolName);
        if (it == g_ToolRegistry.end())
        {
            nlohmann::json err;
            err["success"] = false;
            err["error"] = std::string("Unknown tool: ") + toolName;
            SafeWriteResult(err.dump(), outResult, maxResultLen);
            return 0;
        }

        std::string jsonResult = it->second(args);
        SafeWriteResult(jsonResult, outResult, maxResultLen);
        return 1;
    }
    catch (const std::exception& e)
    {
        nlohmann::json err;
        err["success"] = false;
        err["error"] = std::string("[AITools] Internal exception: ") + e.what();
        SafeWriteResult(err.dump(), outResult, maxResultLen);
        return 0;
    }
    catch (...)
    {
        nlohmann::json err;
        err["success"] = false;
        err["error"] = "[AITools] Unknown fatal exception.";
        SafeWriteResult(err.dump(), outResult, maxResultLen);
        return 0;
    }
}
