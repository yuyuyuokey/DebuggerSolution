#include "CDisassembler.h"
#include <stdio.h>
#include <malloc.h>
#include "Zydis.h" // 仅在此CPP中包含 Zydis

CDisassembler::CDisassembler()
    : m_bZydisReady(FALSE), m_dwNextDisasmAddr(0), m_bHasNextDisasmAddr(FALSE)
{
    m_pDecoder = malloc(sizeof(ZydisDecoder));
    m_pFormatter = malloc(sizeof(ZydisFormatter));
}

CDisassembler::~CDisassembler() {
    if (m_pDecoder) free(m_pDecoder);
    if (m_pFormatter) free(m_pFormatter);
}

bool CDisassembler::Init() {
    if (m_bZydisReady) return true;

    if (!ZYAN_SUCCESS(ZydisDecoderInit((ZydisDecoder*)m_pDecoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32))) {
        printf("Failed to initialize Zydis decoder.\n");
        return false;
    }

    if (!ZYAN_SUCCESS(ZydisFormatterInit((ZydisFormatter*)m_pFormatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
        printf("Failed to initialize Zydis formatter.\n");
        return false;
    }

    ZydisFormatterSetProperty((ZydisFormatter*)m_pFormatter, ZYDIS_FORMATTER_PROP_UPPERCASE_MNEMONIC, ZYAN_TRUE);
    ZydisFormatterSetProperty((ZydisFormatter*)m_pFormatter, ZYDIS_FORMATTER_PROP_UPPERCASE_REGISTERS, ZYAN_TRUE);
    ZydisFormatterSetProperty((ZydisFormatter*)m_pFormatter, ZYDIS_FORMATTER_PROP_HEX_UPPERCASE, ZYAN_TRUE);

    m_bZydisReady = TRUE;
    return true;
}

int CDisassembler::DisAsm(HANDLE hProcess, DWORD dwAddress, int nLine, DWORD dwThreadId) {
    if (!m_bZydisReady) return 0;
    if (nLine <= 0) nLine = 10;

    DWORD dwStartAddr;
    if (dwAddress != 0) {
        dwStartAddr = dwAddress;
        m_dwNextDisasmAddr = dwStartAddr;
        m_bHasNextDisasmAddr = TRUE;
    }
    else if (m_bHasNextDisasmAddr) {
        dwStartAddr = m_dwNextDisasmAddr;
    }
    else {
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, dwThreadId);
        if (!hThread) return 0;
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(hThread, &ctx);
        CloseHandle(hThread);
        dwStartAddr = ctx.Eip;

        if (dwStartAddr < 0x10000 || dwStartAddr > 0x7FFEFFFF) {
            m_bHasNextDisasmAddr = FALSE;
            return 0;
        }
    }

    size_t maxRead = (size_t)nLine * 16;
    BYTE* buffer = (BYTE*)malloc(maxRead);
    memset(buffer, 0, maxRead);

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)dwStartAddr, buffer, maxRead, &bytesRead) || bytesRead == 0) {
        m_bHasNextDisasmAddr = FALSE;
        free(buffer);
        return 0;
    }

    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    char formatBuffer[256];
    int linesPrinted = 0;

    printf("Disassembly at 0x%08X:\n----------------------------------------\n", dwStartAddr);

    while (linesPrinted < nLine && offset < bytesRead) {
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull((ZydisDecoder*)m_pDecoder, buffer + offset, bytesRead - offset, &instruction, operands))) {
            ZydisFormatterFormatInstruction((ZydisFormatter*)m_pFormatter, &instruction, operands, instruction.operand_count_visible, formatBuffer, sizeof(formatBuffer), dwStartAddr + offset, NULL);
            printf("0x%08X  ", dwStartAddr + (DWORD)offset);
            for (int i = 0; i < (int)instruction.length; i++) printf("%02X ", buffer[offset + i]);
            for (int i = (int)instruction.length; i < 8; i++) printf("   ");
            printf("%s\n", formatBuffer);
            offset += instruction.length;
            linesPrinted++;
        }
        else {
            offset++;
        }
    }
    m_dwNextDisasmAddr = dwStartAddr + (DWORD)offset;
    m_bHasNextDisasmAddr = TRUE;
    free(buffer);
    return linesPrinted;
}

bool CDisassembler::IsCallInstruction(BYTE* buffer, SIZE_T length, DWORD& outInstrLength) {
    if (!m_bZydisReady) return false;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    if (ZYAN_SUCCESS(ZydisDecoderDecodeFull((ZydisDecoder*)m_pDecoder, buffer, length, &instruction, operands))) {
        outInstrLength = instruction.length;
        return instruction.mnemonic == ZYDIS_MNEMONIC_CALL;
    }
    return false;
}

int CDisassembler::GetDisasmString(HANDLE hProcess, DWORD dwAddress, int nLine, DWORD dwThreadId, char* outBuffer, int bufferSize)
{
    if (!m_bZydisReady || !outBuffer || bufferSize <= 0) return 0;
    if (nLine <= 0) nLine = 10;
    outBuffer[0] = '\0'; // 清空缓冲区

    DWORD dwStartAddr = dwAddress;
    if (dwStartAddr == 0) {
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, dwThreadId);
        if (!hThread) return 0;
        CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(hThread, &ctx);
        CloseHandle(hThread);
        dwStartAddr = ctx.Eip;
    }

    size_t maxRead = (size_t)nLine * 16;
    BYTE* buffer = (BYTE*)malloc(maxRead);
    memset(buffer, 0, maxRead);

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)dwStartAddr, buffer, maxRead, &bytesRead) || bytesRead == 0) {
        free(buffer);
        return 0;
    }

    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    char formatBuffer[256];
    int linesPrinted = 0;

    while (linesPrinted < nLine && offset < bytesRead) {
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull((ZydisDecoder*)m_pDecoder, buffer + offset, bytesRead - offset, &instruction, operands))) {
            ZydisFormatterFormatInstruction((ZydisFormatter*)m_pFormatter, &instruction, operands, instruction.operand_count_visible, formatBuffer, sizeof(formatBuffer), dwStartAddr + offset, NULL);

            // 1. 组装 Hex 机器码字符串
            char hexStr[64] = { 0 };
            for (int i = 0; i < (int)instruction.length; i++) {
                char tmp[8];
                sprintf_s(tmp, "%02X ", buffer[offset + i]);
                strcat_s(hexStr, sizeof(hexStr), tmp);
            }

            // 2. 组装 OD 风格的一行 (首行加上 -> 箭头指示当前 EIP)
            char lineBuf[256];
            const char* pointer = (linesPrinted == 0) ? "->" : "  ";
            sprintf_s(lineBuf, "%s %08X | %-22s | %s\r\n", pointer, dwStartAddr + (DWORD)offset, hexStr, formatBuffer);

            // 3. 追加到输出缓冲区
            strcat_s(outBuffer, bufferSize, lineBuf);

            offset += instruction.length;
            linesPrinted++;
        }
        else {
            offset++;
        }
    }
    free(buffer);
    return linesPrinted;
}

// 获取结构化反汇编列表
int CDisassembler::GetDisasmList(HANDLE hProcess, DWORD dwAddress, int nLine, DWORD dwThreadId, InstrInfo* outBuffer)
{
    if (!m_bZydisReady || !outBuffer) return 0;
    if (nLine <= 0) nLine = 10;

    DWORD dwStartAddr = dwAddress;
    if (dwStartAddr == 0) {
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, dwThreadId);
        if (!hThread) return 0;
        CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(hThread, &ctx);
        CloseHandle(hThread);
        dwStartAddr = ctx.Eip;
    }

    size_t maxRead = (size_t)nLine * 16;
    BYTE* buffer = (BYTE*)malloc(maxRead);
    memset(buffer, 0, maxRead);

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)dwStartAddr, buffer, maxRead, &bytesRead) || bytesRead == 0) {
        free(buffer); return 0;
    }

    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    char formatBuffer[256];
    int linesPrinted = 0;

    while (linesPrinted < nLine && offset < bytesRead) {
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull((ZydisDecoder*)m_pDecoder, buffer + offset, bytesRead - offset, &instruction, operands))) {
            ZydisFormatterFormatInstruction((ZydisFormatter*)m_pFormatter, &instruction, operands, instruction.operand_count_visible, formatBuffer, sizeof(formatBuffer), dwStartAddr + offset, NULL);

            // 填充结构体
            outBuffer[linesPrinted].address = dwStartAddr + (DWORD)offset;

            char hexStr[32] = { 0 };
            for (int i = 0; i < (int)instruction.length; i++) {
                char tmp[8]; sprintf_s(tmp, "%02X ", buffer[offset + i]);
                strcat_s(hexStr, sizeof(hexStr), tmp);
            }
            // 严格传入缓冲区的大小，消除 C2660 报错
            strcpy_s(outBuffer[linesPrinted].hexCode, sizeof(outBuffer[linesPrinted].hexCode), hexStr);
            strcpy_s(outBuffer[linesPrinted].assembly, sizeof(outBuffer[linesPrinted].assembly), formatBuffer);

            offset += instruction.length;
            linesPrinted++;
        }
        else offset++;
    }
    free(buffer);
    return linesPrinted;
}


int CDisassembler::GetGlobalCount() const {
    return (int)m_GlobalInstrs.size();
}

bool CDisassembler::GetGlobalItem(int index, InstrInfo* outInfo) const {
    if (index < 0 || index >= m_GlobalInstrs.size() || !outInfo) return false;
    *outInfo = m_GlobalInstrs[index];
    return true;
}

// 采用极速二分查找法寻找 EIP
int CDisassembler::FindIndexByAddress(DWORD addr) const {
    int left = 0, right = (int)m_GlobalInstrs.size() - 1;
    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (m_GlobalInstrs[mid].address == addr) return mid;
        if (m_GlobalInstrs[mid].address < addr) left = mid + 1;
        else right = mid - 1;
    }
    return -1; // 没找到
}

// 1. 核心解析：提取程序的 .text 代码段并全部反汇编！
bool CDisassembler::BuildGlobalDisasm(HANDLE hProcess, DWORD imageBase)
{
    m_GlobalInstrs.clear();
    if (!m_bZydisReady) return false;

    m_dwMainModuleBase = imageBase; // 保存主模块基址

    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(hProcess, (LPCVOID)imageBase, &dosHeader, sizeof(dosHeader), NULL) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return false;

    IMAGE_NT_HEADERS32 ntHeaders;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(imageBase + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), NULL) || ntHeaders.Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD textVA = imageBase + ntHeaders.OptionalHeader.BaseOfCode;
    DWORD textSize = ntHeaders.OptionalHeader.SizeOfCode;
    if (textSize == 0) return false;

    m_dwTextVA = textVA;
    m_dwTextSize = textSize;

    BYTE* buffer = (BYTE*)malloc(textSize);
    if (!buffer) return false;

    SIZE_T bytesRead = 0;
    ReadProcessMemory(hProcess, (LPCVOID)textVA, buffer, textSize, &bytesRead);

    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    char formatBuffer[256];

    while (offset < bytesRead) {
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull((ZydisDecoder*)m_pDecoder, buffer + offset, bytesRead - offset, &instruction, operands))) {
            ZydisFormatterFormatInstruction((ZydisFormatter*)m_pFormatter, &instruction, operands, instruction.operand_count_visible, formatBuffer, sizeof(formatBuffer), textVA + offset, NULL);

            InstrInfo info;
            info.address = textVA + (DWORD)offset;

            char hexStr[128] = { 0 };
            for (int i = 0; i < (int)instruction.length; i++) {
                char tmp[8]; sprintf_s(tmp, "%02X ", buffer[offset + i]);
                strcat_s(hexStr, sizeof(hexStr), tmp);
            }
            strncpy_s(info.hexCode, sizeof(info.hexCode), hexStr, _TRUNCATE);
            strncpy_s(info.assembly, sizeof(info.assembly), formatBuffer, _TRUNCATE);

            // ==========================================
            // 【新增】：黑科技 - 智能字符串探测引擎！
            // ==========================================
            info.comment[0] = '\0'; // 默认注释为空

            // 遍历指令的所有操作数，寻找可能的内存地址
            for (int i = 0; i < instruction.operand_count_visible; i++) {
                ZyanU64 targetAddr = 0;

                // 1. 如果操作数是一个立即数 (如 PUSH 0x402088)
                if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    targetAddr = operands[i].imm.value.u;
                }
                // 2. 如果操作数是一个内存偏移 (如 MOV EAX, [0x4020CA])
                else if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    // 【终极修复】：使用 Zydis 官方底层函数，彻底规避结构体版本差异！
                    ZydisCalcAbsoluteAddress(&instruction, &operands[i], info.address, &targetAddr);
                }

                // 如果算出的是一个合理的 Windows 内存地址 (大于 0x10000)
                if (targetAddr > 0x10000) {
                    char strBuf[32] = { 0 };
                    SIZE_T rb = 0;
                    // 偷偷去读目标进程的这块内存
                    if (ReadProcessMemory(hProcess, (LPCVOID)targetAddr, strBuf, 30, &rb) && rb > 0) {
                        // 检查读出来的字节是不是连续的、可打印的 ASCII 字符？
                        bool isString = true;
                        int strLen = 0;
                        for (int k = 0; k < rb; k++) {
                            if (strBuf[k] == '\0') break; // 遇到字符串结尾
                            if (strBuf[k] < 32 || strBuf[k] > 126) { isString = false; break; } // 不是正常字符
                            strLen++;
                        }

                        // 如果连续可打印字符大于等于 3 个，我们就认定它是一个隐藏的字符串！
                        if (isString && strLen >= 3) {
                            sprintf_s(info.comment, sizeof(info.comment), "ASCII \"%s\"", strBuf);
                            break; // 找到了注释就跳出循环
                        }
                    }
                }
            }
            // ==========================================

            m_GlobalInstrs.push_back(info);
            offset += instruction.length;
        }
        else {
            offset++;
        }
    }
    free(buffer);

    m_bIsShowingMain = true;
    return true;
}

// ========================================================
// 【终极版】：任意模块领空切换与全局反汇编引擎！
// ========================================================
bool CDisassembler::EnsureDisasmForAddress(HANDLE hProcess, DWORD addr)
{
    if (m_dwTextVA != 0 && addr >= m_dwTextVA && addr < m_dwTextVA + m_dwTextSize) {
        return true;
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        DWORD moduleBase = (DWORD)mbi.AllocationBase;

        IMAGE_DOS_HEADER dosHeader;
        if (ReadProcessMemory(hProcess, (LPCVOID)moduleBase, &dosHeader, sizeof(dosHeader), NULL) && dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {

            IMAGE_NT_HEADERS32 ntHeaders;
            if (ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), NULL) && ntHeaders.Signature == IMAGE_NT_SIGNATURE) {

                DWORD textVA = moduleBase + ntHeaders.OptionalHeader.BaseOfCode;
                DWORD textSize = ntHeaders.OptionalHeader.SizeOfCode;

                if (addr >= textVA && addr < textVA + textSize) {
                    return BuildGlobalDisasm(hProcess, moduleBase);
                }
            }
        }
    }

    m_GlobalInstrs.clear();
    m_dwTextVA = 0;

    DWORD size = 0x1000;
    BYTE* buffer = (BYTE*)malloc(size);
    SIZE_T bytesRead = 0;
    ReadProcessMemory(hProcess, (LPCVOID)addr, buffer, size, &bytesRead);
    if (bytesRead == 0) { free(buffer); return false; }

    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    char formatBuffer[256];

    while (offset < bytesRead && m_GlobalInstrs.size() < 300) {
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull((ZydisDecoder*)m_pDecoder, buffer + offset, bytesRead - offset, &instruction, operands))) {
            ZydisFormatterFormatInstruction((ZydisFormatter*)m_pFormatter, &instruction, operands, instruction.operand_count_visible, formatBuffer, sizeof(formatBuffer), addr + offset, NULL);

            InstrInfo info;
            info.address = addr + (DWORD)offset;

            char hexStr[128] = { 0 };
            for (int i = 0; i < (int)instruction.length; i++) {
                char tmp[8]; sprintf_s(tmp, "%02X ", buffer[offset + i]);
                strcat_s(hexStr, sizeof(hexStr), tmp);
            }
            strncpy_s(info.hexCode, sizeof(info.hexCode), hexStr, _TRUNCATE);
            strncpy_s(info.assembly, sizeof(info.assembly), formatBuffer, _TRUNCATE);

            // ==========================================
            // 同步加入：智能字符串探测引擎！
            // ==========================================
            info.comment[0] = '\0';
            for (int i = 0; i < instruction.operand_count_visible; i++) {
                ZyanU64 targetAddr = 0;
                if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    targetAddr = operands[i].imm.value.u;
                }
                else if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    ZydisCalcAbsoluteAddress(&instruction, &operands[i], info.address, &targetAddr);
                }

                if (targetAddr > 0x10000) {
                    char strBuf[32] = { 0 };
                    SIZE_T rb = 0;
                    if (ReadProcessMemory(hProcess, (LPCVOID)targetAddr, strBuf, 30, &rb) && rb > 0) {
                        bool isString = true;
                        int strLen = 0;
                        for (int k = 0; k < rb; k++) {
                            if (strBuf[k] == '\0') break;
                            if (strBuf[k] < 32 || strBuf[k] > 126) { isString = false; break; }
                            strLen++;
                        }
                        if (isString && strLen >= 3) {
                            sprintf_s(info.comment, sizeof(info.comment), "ASCII \"%s\"", strBuf);
                            break;
                        }
                    }
                }
            }
            // ==========================================

            m_GlobalInstrs.push_back(info);
            offset += instruction.length;
        }
        else offset++;
    }
    free(buffer);
    return true;
}