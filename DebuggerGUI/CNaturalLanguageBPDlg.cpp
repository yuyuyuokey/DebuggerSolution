#include "pch.h"
#include "CNaturalLanguageBPDlg.h"
#include "DebuggerGUIDlg.h"
#include "DebuggerAPI.h"
#include "httplib.h"
#include "json.hpp"
#include <sstream>
#include <iostream>
#include <cctype>

static std::string CStringToUTF8(const CString& str)
{
    int len = WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)str, str.GetLength(), NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    std::string result(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)str, str.GetLength(), &result[0], len, NULL, NULL);
    return result;
}

static std::string GetDeepSeekApiKey()
{
    char key[512] = { 0 };
    DWORD len = GetEnvironmentVariableA("DEEPSEEK_API_KEY", key, (DWORD)sizeof(key));
    if (len == 0 || len >= sizeof(key))
    {
        return "";
    }
    return key;
}

static bool TryResolveApiFromText(const CString& userInput, CString* outApiName, DWORD* outAddress)
{
    if (outApiName) outApiName->Empty();
    if (outAddress) *outAddress = 0;

    CStringA ansiInput(userInput);
    std::string text = (LPCSTR)ansiInput;
    std::string token;

    auto flushToken = [&](void) -> bool
    {
        if (token.size() < 3)
        {
            token.clear();
            return false;
        }

        DWORD addr = dbg_ResolveApiAddress(token.c_str());
        if (addr != 0)
        {
            if (outApiName) *outApiName = CString(token.c_str());
            if (outAddress) *outAddress = addr;
            token.clear();
            return true;
        }

        token.clear();
        return false;
    };

    for (size_t i = 0; i < text.size(); ++i)
    {
        const unsigned char ch = (unsigned char)text[i];
        if (std::isalnum(ch) || ch == '_')
        {
            token.push_back((char)ch);
        }
        else
        {
            if (flushToken())
                return true;
        }
    }

    return flushToken();
}

static bool TryGetAutoBreakpointAddress(CWnd* pOwner, DWORD* outAddress)
{
    if (!outAddress)
        return false;

    *outAddress = 0;

    CDebuggerGUIDlg* pMainDlg = dynamic_cast<CDebuggerGUIDlg*>(pOwner);
    if (!pMainDlg)
        pMainDlg = dynamic_cast<CDebuggerGUIDlg*>(AfxGetMainWnd());

    if (pMainDlg)
    {
        CListCtrl* pList = (CListCtrl*)pMainDlg->GetDlgItem(IDC_LIST_DISASM);
        if (pList)
        {
            POSITION pos = pList->GetFirstSelectedItemPosition();
            if (pos)
            {
                int nItem = pList->GetNextSelectedItem(pos);
                InstrInfo info = { 0 };
                if (dbg_GetGlobalDisasmItem(nItem, &info))
                {
                    *outAddress = info.address;
                    return true;
                }
            }
        }

        if (pMainDlg->m_currentThreadId != 0)
        {
            RegInfo regs = { 0 };
            if (dbg_GetRegs(pMainDlg->m_currentThreadId, &regs))
            {
                *outAddress = regs.eip;
                return true;
            }
        }

        if (pMainDlg->m_currentEIP != 0)
        {
            *outAddress = pMainDlg->m_currentEIP;
            return true;
        }
    }

    return false;
}

CNaturalLanguageBPDlg::CNaturalLanguageBPDlg(CWnd* pParent)
    : CDialogEx(IDD_DLG_NL_BP, pParent)
{
    m_result.address = 0;
    m_result.targetSymbol = _T("");
    m_result.condition = _T("");
    m_result.description = _T("");
    m_result.rawInput = _T("");
    m_result.isValid = false;
    m_result.isConditional = false;
}

void CNaturalLanguageBPDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_EDIT_NL_INPUT, m_editInput);
    DDX_Control(pDX, IDC_EDIT_NL_OUTPUT, m_editOutput);
    DDX_Control(pDX, IDC_EDIT_NL_CONDITION, m_editCondition);
    DDX_Control(pDX, IDC_STATIC_NL_STATUS, m_staticStatus);
}

BEGIN_MESSAGE_MAP(CNaturalLanguageBPDlg, CDialogEx)
    ON_BN_CLICKED(IDC_BTN_NL_GENERATE, &CNaturalLanguageBPDlg::OnBnClickedGenerate)
    ON_BN_CLICKED(IDC_BTN_NL_SETBP, &CNaturalLanguageBPDlg::OnBnClickedSetBreakpoint)
END_MESSAGE_MAP()

BOOL CNaturalLanguageBPDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();
    SetWindowText(_T("Natural Language Conditional Breakpoint"));

    CString defaultInput;
    defaultInput = _T("Break when EAX equals 0x12345678");
    m_editInput.SetWindowText(defaultInput);
    SetStatus(_T("Ready. Enter your natural language description and click Generate."));

    return TRUE;
}

void CNaturalLanguageBPDlg::SetStatus(const CString& text, bool isError)
{
    m_staticStatus.SetWindowText(text);
}

CString CNaturalLanguageBPDlg::BuildNLBPrompt(const CString& userInput)
{
    CString prompt;
    prompt = _T("You are an expert in x86 debugging and breakpoints. ");
    prompt += _T("The user may want either an unconditional breakpoint or a conditional breakpoint described in natural language. ");
    prompt += _T("Your task is to parse the natural language description and generate the appropriate breakpoint configuration. ");
    prompt += _T("\n\n");
    prompt += _T("User's natural language description: \"");
    prompt += userInput;
    prompt += _T("\"");
    prompt += _T("\n\n");
    prompt += _T("Please respond with a JSON object in the following format exactly, with no additional text:\n");
    prompt += _T("{\n");
    prompt += _T("  \"is_valid\": true/false,\n");
    prompt += _T("  \"breakpoint_type\": \"unconditional\" or \"conditional\",\n");
    prompt += _T("  \"address\": \"0x00401234\" or \"auto\" or \"api:MessageBoxA\",\n");
    prompt += _T("  \"condition\": \"\" or \"EAX == 0x12345678\",\n");
    prompt += _T("  \"description\": \"Break on call to MessageBoxA\" or \"Break when EAX equals the address of Admin string\",\n");
    prompt += _T("  \"explanation\": \"Short explanation\"\n");
    prompt += _T("}\n");
    prompt += _T("\n");
    prompt += _T("Examples:\n");
    prompt += _T("- For \"break at MessageBoxA\": set breakpoint_type to \"unconditional\", address to \"api:MessageBoxA\", condition to \"\".\n");
    prompt += _T("- For \"在调用MessageBoxA这个API的地方下断点\": set breakpoint_type to \"unconditional\", address to \"api:MessageBoxA\", condition to \"\".\n");
    prompt += _T("- For \"break when EAX == 0x00402000\": set breakpoint_type to \"conditional\", address to \"auto\", condition to \"EAX == 0x00402000\".\n");
    prompt += _T("\n");
    prompt += _T("Condition syntax examples:\n");
    prompt += _T("- \"EAX == 0x00402000\"\n");
    prompt += _T("- \"ECX == 10\"\n");
    prompt += _T("- \"EDX != 0\"\n");
    prompt += _T("- \"ESI == EDI\"\n");
    prompt += _T("\n");
    prompt += _T("API-name breakpoint requests are valid even when condition is empty. ");
    prompt += _T("Only output the JSON, no other text. If you cannot understand the request, set is_valid to false.");
    return prompt;
}

bool CNaturalLanguageBPDlg::ParseAIResponse(const std::string& aiResponse, GeneratedBreakpoint* outResult)
{
    if (!outResult) return false;

    size_t jsonStart = aiResponse.find('{');
    size_t jsonEnd = aiResponse.rfind('}');
    
    if (jsonStart == std::string::npos || jsonEnd == std::string::npos || jsonEnd <= jsonStart)
    {
        return false;
    }

    std::string jsonStr = aiResponse.substr(jsonStart, jsonEnd - jsonStart + 1);

    try
    {
        auto j = nlohmann::json::parse(jsonStr);

        outResult->isValid = j.value("is_valid", false);
        outResult->isConditional = (j.value("breakpoint_type", std::string("conditional")) == "conditional");
        outResult->targetSymbol = _T("");
        
        if (j.contains("address") && j["address"].is_string())
        {
            std::string addrStr = j["address"].get<std::string>();
            if (addrStr == "auto" || addrStr.empty())
            {
                outResult->address = 0;
            }
            else
            {
                if (addrStr.rfind("api:", 0) == 0 || addrStr.rfind("API:", 0) == 0)
                {
                    outResult->targetSymbol = CString(addrStr.substr(4).c_str());
                    outResult->address = 0;
                }
                else if (addrStr.compare(0, 2, "0x") == 0 || addrStr.compare(0, 2, "0X") == 0)
                    outResult->address = (DWORD)strtoul(addrStr.c_str() + 2, nullptr, 16);
                else
                    outResult->address = (DWORD)strtoul(addrStr.c_str(), nullptr, 16);
            }
        }

        if (j.contains("condition") && j["condition"].is_string())
        {
            std::string cond = j["condition"].get<std::string>();
            outResult->condition = CString(cond.c_str());
        }

        if (j.contains("description") && j["description"].is_string())
        {
            std::string desc = j["description"].get<std::string>();
            outResult->description = CString(desc.c_str());
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}

void CNaturalLanguageBPDlg::OnBnClickedGenerate()
{
    CString userInput;
    m_editInput.GetWindowText(userInput);

    if (userInput.IsEmpty())
    {
        SetStatus(_T("Please enter a natural language description first."), true);
        return;
    }

    m_result.rawInput = userInput;
    m_result.address = 0;
    m_result.targetSymbol = _T("");
    m_result.condition = _T("");
    m_result.description = _T("");
    m_result.isValid = false;
    m_result.isConditional = false;
    SetStatus(_T("Generating breakpoint configuration..."));

    std::string apiKey = GetDeepSeekApiKey();
    if (apiKey.empty())
    {
        SetStatus(_T("Error: DEEPSEEK_API_KEY environment variable not set."), true);
        return;
    }

    try
    {
        httplib::SSLClient cli("api.deepseek.com", 443);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(60, 0);
        cli.set_write_timeout(60, 0);

        nlohmann::json messages = nlohmann::json::array();
        messages.push_back({
            {"role", "system"},
            {"content", "You are an expert in x86 debugging and conditional breakpoints. Generate only valid JSON as requested."}
        });
        messages.push_back({
            {"role", "user"},
            {"content", CStringToUTF8(BuildNLBPrompt(userInput))}
        });

        nlohmann::json req;
        req["model"] = "deepseek-coder";
        req["messages"] = messages;
        req["stream"] = false;
        req["temperature"] = 0.1;
        req["top_p"] = 0.9;

        httplib::Headers headers = {
            {"Authorization", std::string("Bearer ") + apiKey},
            {"Content-Type", "application/json"}
        };

        auto res = cli.Post("/chat/completions", headers, req.dump(), "application/json");

        if (!res || res->status != 200)
        {
            SetStatus(_T("Error: Failed to communicate with AI service."), true);
            return;
        }

        auto j = nlohmann::json::parse(res->body);
        std::string aiResponse = j["choices"][0]["message"]["content"].get<std::string>();

        CString outputText;
        outputText.Format(_T("AI Response:\n\n%s"), CString(aiResponse.c_str()));
        m_editOutput.SetWindowText(outputText);

        if (ParseAIResponse(aiResponse, &m_result))
        {
            if (m_result.isValid)
            {
                m_editCondition.SetWindowText(m_result.condition);

                CString status;
                if (!m_result.targetSymbol.IsEmpty())
                    status.Format(_T("Success! API breakpoint target: %s"), m_result.targetSymbol);
                else if (!m_result.condition.IsEmpty())
                    status.Format(_T("Success! Condition: %s"), m_result.condition);
                else
                    status = _T("Success! Unconditional breakpoint generated.");
                SetStatus(status);
            }
            else
            {
                CString apiName;
                DWORD apiAddr = 0;
                if (TryResolveApiFromText(userInput, &apiName, &apiAddr))
                {
                    m_result.isValid = true;
                    m_result.isConditional = false;
                    m_result.address = 0;
                    m_result.targetSymbol = apiName;
                    m_result.condition = _T("");
                    m_result.description.Format(_T("Break on call to %s"), apiName);
                    m_editCondition.SetWindowText(_T(""));

                    CString status;
                    status.Format(_T("Fallback success! API breakpoint target: %s"), apiName);
                    SetStatus(status);
                }
                else
                {
                    SetStatus(_T("AI could not understand the request. Please try rephrasing."), true);
                }
            }
        }
        else
        {
            CString apiName;
            DWORD apiAddr = 0;
            if (TryResolveApiFromText(userInput, &apiName, &apiAddr))
            {
                m_result.isValid = true;
                m_result.isConditional = false;
                m_result.address = 0;
                m_result.targetSymbol = apiName;
                m_result.condition = _T("");
                m_result.description.Format(_T("Break on call to %s"), apiName);
                m_editCondition.SetWindowText(_T(""));

                CString status;
                status.Format(_T("Fallback success! API breakpoint target: %s"), apiName);
                SetStatus(status);
            }
            else
            {
                SetStatus(_T("Error: Failed to parse AI response."), true);
            }
        }
    }
    catch (const std::exception& e)
    {
        CString err;
        err.Format(_T("Error: %s"), CString(e.what()));
        SetStatus(err, true);
    }
}

void CNaturalLanguageBPDlg::OnBnClickedSetBreakpoint()
{
    if (!m_result.isValid)
    {
        SetStatus(_T("Please generate a valid breakpoint first."), true);
        return;
    }

    DWORD address = m_result.address;
    if (!m_result.targetSymbol.IsEmpty())
    {
        CStringA ansiApiName(m_result.targetSymbol);
        address = dbg_ResolveApiAddress((LPCSTR)ansiApiName);
        if (address == 0)
        {
            CString err;
            err.Format(_T("Error: Could not resolve API address for %s"), m_result.targetSymbol);
            SetStatus(err, true);
            return;
        }
    }
    else if (address == 0)
    {
        if (!TryGetAutoBreakpointAddress(GetParent(), &address))
        {
            SetStatus(_T("Error: Could not determine breakpoint address automatically. Please select a disassembly line or pause the program first."), true);
            return;
        }
    }

    if (!dbg_HasBreakpoint(address))
    {
        bool success = false;
        if (!m_result.condition.IsEmpty())
        {
            CStringA conditionA(m_result.condition);
            success = dbg_SetConditionalBreakpoint(address, (LPCSTR)conditionA);
        }
        else
        {
            success = dbg_SetBreakpoint(address);
        }
        
        if (success)
        {
            CString msg;
            if (!m_result.targetSymbol.IsEmpty())
                msg.Format(_T("Breakpoint set at 0x%08X\nTarget API: %s"), address, m_result.targetSymbol);
            else if (!m_result.condition.IsEmpty())
                msg.Format(_T("Conditional breakpoint set at 0x%08X\nCondition: %s"), address, m_result.condition);
            else
                msg.Format(_T("Breakpoint set at 0x%08X"), address);
            AfxMessageBox(msg);
            SetStatus(_T("Breakpoint set successfully!"));
        }
        else
        {
            SetStatus(_T("Error: Failed to set breakpoint."), true);
        }
    }
    else
    {
        CString msg;
        msg.Format(_T("Breakpoint already exists at 0x%08X"), address);
        AfxMessageBox(msg);
        SetStatus(_T("Breakpoint already exists."));
    }
}
