#define _CRT_SECURE_NO_WARNINGS
#include "CMyDebug.h"
#include <stdio.h>

CMyDebug::CMyDebug()
    : m_IsSystemBreakPoint(FALSE)
    , m_hProcess(NULL)
    , m_pPromptCallback(NULL)
    , m_dwStepOverBPAddr(0)
    , m_bIsUserStepping(FALSE)
    , m_dwStepOverTempBPAddr(0)
    , m_TempBPOrigByte(0)
    , m_bRunning(TRUE)
{
}

CMyDebug::~CMyDebug() {
    if (m_hProcess) CloseHandle(m_hProcess);
}

void CMyDebug::SetPromptCallback(PromptCallback cb) {
    m_pPromptCallback = cb;
}

int CMyDebug::BeginDebug(LPCWSTR lpPath) {
    STARTUPINFOW si = { sizeof(si) }; // <--- 改为 STARTUPINFOW
    PROCESS_INFORMATION pi = { 0 };

    // <--- 改为显式调用 CreateProcessW
    if (!CreateProcessW(lpPath, NULL, NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        printf("CreateProcess Error: %d\n", GetLastError());
        return 1;
    }

    while (m_bRunning) {
        if (!WaitForDebugEvent(&m_DebugEvent, INFINITE)) break;
        DWORD dwContinueStatus = DBG_CONTINUE;

        switch (m_DebugEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:    dwContinueStatus = OnDebugEvent(); break;
        case CREATE_PROCESS_DEBUG_EVENT:dwContinueStatus = OnCreateProcess(); break;
        case CREATE_THREAD_DEBUG_EVENT: dwContinueStatus = OnCreateThread(); break;
        case EXIT_PROCESS_DEBUG_EVENT:  dwContinueStatus = OnExitProcess(); break;
        case EXIT_THREAD_DEBUG_EVENT:   dwContinueStatus = OnExitThread(); break;
        case LOAD_DLL_DEBUG_EVENT:      dwContinueStatus = OnloadDll(); break;
        case UNLOAD_DLL_DEBUG_EVENT:    dwContinueStatus = OnUnloadDll(); break;
        case OUTPUT_DEBUG_STRING_EVENT: dwContinueStatus = OnOutPutDebugString(); break;
        }

        if (!ContinueDebugEvent(m_DebugEvent.dwProcessId, m_DebugEvent.dwThreadId, dwContinueStatus)) break;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
}

int CMyDebug::OnDebugEvent() {
    EXCEPTION_RECORD* pInfo = &m_DebugEvent.u.Exception.ExceptionRecord;
    switch (pInfo->ExceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION:
        printf("\n[!] Access Violation at 0x%08X\n", (DWORD)pInfo->ExceptionAddress);
        m_Disasm.DisAsm(m_hProcess, (DWORD)pInfo->ExceptionAddress, 5, m_DebugEvent.dwThreadId);
        return DBG_EXCEPTION_NOT_HANDLED;

    case EXCEPTION_BREAKPOINT:
        return OnExecBreakPoint();

    case EXCEPTION_SINGLE_STEP: {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_DebugEvent.dwThreadId);
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(hThread, &ctx);

        // 硬件断点逻辑
        if (ctx.Dr6 & 0x0F) {
            DWORD hitAddr = (ctx.Dr6 & 1) ? ctx.Dr0 : (ctx.Dr6 & 2) ? ctx.Dr1 : (ctx.Dr6 & 4) ? ctx.Dr2 : ctx.Dr3;
            printf("\nHardware Breakpoint hit at 0x%08X! (EIP: 0x%08X)\n", hitAddr, ctx.Eip);
            ctx.Dr6 = 0;
            ctx.EFlags |= 0x10000; // RF flag
            SetThreadContext(hThread, &ctx);

            m_Disasm.DisAsm(m_hProcess, ctx.Eip, 1, m_DebugEvent.dwThreadId);
            if (m_pPromptCallback) m_pPromptCallback(this); // 转交UI
            CloseHandle(hThread);
            return DBG_CONTINUE;
        }

        // 隐式步过逻辑恢复
        if (m_dwStepOverBPAddr != 0) {
            BYTE cc = 0xCC;
            WriteProcessMemory(m_hProcess, (LPVOID)m_dwStepOverBPAddr, &cc, 1, NULL);
            FlushInstructionCache(m_hProcess, (LPVOID)m_dwStepOverBPAddr, 1);
            m_dwStepOverBPAddr = 0;
        }

        // 普通单步UI交互
        if (!m_bIsUserStepping) { CloseHandle(hThread); return DBG_CONTINUE; }

        m_Disasm.DisAsm(m_hProcess, ctx.Eip, 1, m_DebugEvent.dwThreadId);
        m_bIsUserStepping = FALSE;
        if (m_pPromptCallback) m_pPromptCallback(this);

        CloseHandle(hThread);
        return DBG_CONTINUE;
    }
    }
    return DBG_EXCEPTION_NOT_HANDLED;
}

int CMyDebug::OnExecBreakPoint() {
    DWORD dwExAddr = (DWORD)m_DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;

    if (!m_IsSystemBreakPoint) {
        m_IsSystemBreakPoint = TRUE;
        printf("\nSystem Breakpoint reached at 0x%08X\n", dwExAddr);
        m_Disasm.DisAsm(m_hProcess, dwExAddr, 1, m_DebugEvent.dwThreadId);
        if (m_pPromptCallback) m_pPromptCallback(this);
        return DBG_CONTINUE;
    }

    if (dwExAddr == m_dwStepOverTempBPAddr) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_DebugEvent.dwThreadId);
        CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_CONTROL; GetThreadContext(hThread, &ctx);
        ctx.Eip = dwExAddr; SetThreadContext(hThread, &ctx);

        WriteProcessMemory(m_hProcess, (LPVOID)dwExAddr, &m_TempBPOrigByte, 1, NULL);
        FlushInstructionCache(m_hProcess, (LPVOID)dwExAddr, 1);
        m_dwStepOverTempBPAddr = 0;

        printf("\nStep Over stopped at 0x%08X\n", ctx.Eip);
        m_Disasm.DisAsm(m_hProcess, ctx.Eip, 1, m_DebugEvent.dwThreadId);
        if (m_pPromptCallback) m_pPromptCallback(this);
        CloseHandle(hThread);
        return DBG_CONTINUE;
    }

    if (m_BPMgr.HasBP(dwExAddr)) {
        printf("\nBreakpoint hit at 0x%08X!\n", dwExAddr);
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_DebugEvent.dwThreadId);
        CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_CONTROL; GetThreadContext(hThread, &ctx);

        ctx.Eip = dwExAddr;
        ctx.EFlags |= 0x100;
        SetThreadContext(hThread, &ctx);

        BYTE orig = m_BPMgr.GetOriginalByte(dwExAddr);
        WriteProcessMemory(m_hProcess, (LPVOID)dwExAddr, &orig, 1, NULL);
        FlushInstructionCache(m_hProcess, (LPVOID)dwExAddr, 1);

        m_dwStepOverBPAddr = dwExAddr;

        m_Disasm.DisAsm(m_hProcess, ctx.Eip, 1, m_DebugEvent.dwThreadId);
        if (m_pPromptCallback) m_pPromptCallback(this);
        CloseHandle(hThread);
        return DBG_CONTINUE;
    }
    return DBG_EXCEPTION_NOT_HANDLED;
}

int CMyDebug::OnCreateThread() {
    m_ThreadMgr.AddThread(m_DebugEvent.dwThreadId);
    return DBG_CONTINUE;
}

int CMyDebug::OnCreateProcess() {
    m_hProcess = m_DebugEvent.u.CreateProcessInfo.hProcess;
    m_Disasm.Init();
    m_ThreadMgr.AddThread(m_DebugEvent.dwThreadId);
    m_BPMgr.Init(m_hProcess, &m_ThreadMgr);

    m_Disasm.BuildGlobalDisasm(m_hProcess, (DWORD)m_DebugEvent.u.CreateProcessInfo.lpBaseOfImage);
    return DBG_CONTINUE;
}

int CMyDebug::OnExitProcess() { m_bRunning = FALSE; return DBG_CONTINUE; }
int CMyDebug::OnExitThread() { m_ThreadMgr.RemoveThread(m_DebugEvent.dwThreadId); return DBG_CONTINUE; }
int CMyDebug::OnloadDll() { return DBG_CONTINUE; }
int CMyDebug::OnUnloadDll() { return DBG_CONTINUE; }
int CMyDebug::OnOutPutDebugString() { return DBG_CONTINUE; }

void CMyDebug::SetUserStepping(BOOL isStepping) { m_bIsUserStepping = isStepping; }

int CMyDebug::SetStep() {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, m_DebugEvent.dwThreadId);
    if (!hThread) return 0;
    CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(hThread, &ctx)) {
        ctx.EFlags |= 0x100; SetThreadContext(hThread, &ctx);
    }
    CloseHandle(hThread);
    return 1;
}

int CMyDebug::SetStepOver() {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, m_DebugEvent.dwThreadId);
    CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(hThread, &ctx);
    CloseHandle(hThread);

    BYTE buffer[16] = { 0 }; SIZE_T rb = 0;
    ReadProcessMemory(m_hProcess, (LPCVOID)ctx.Eip, buffer, sizeof(buffer), &rb);

    DWORD instrLen = 0;
    if (m_Disasm.IsCallInstruction(buffer, rb, instrLen)) {
        DWORD nextAddr = ctx.Eip + instrLen;
        ReadProcessMemory(m_hProcess, (LPCVOID)nextAddr, &m_TempBPOrigByte, 1, NULL);
        BYTE cc = 0xCC; WriteProcessMemory(m_hProcess, (LPVOID)nextAddr, &cc, 1, NULL);
        FlushInstructionCache(m_hProcess, (LPCVOID)nextAddr, 1);
        m_dwStepOverTempBPAddr = nextAddr;
        return 1;
    }
    return SetStep();
}

// （保留你原先非常优秀的辅助显示功能）
// 实现打印常见标志位状态
void CMyDebug::PrintEFlags(DWORD eflags)
{
    // CF:位0, PF:位2, AF:位4, ZF:位6, SF:位7, TF:位8, IF:位9, DF:位10, OF:位11
    printf("EFlags: [ ");
    if (eflags & (1 << 0))  printf("CF "); // 进位
    if (eflags & (1 << 6))  printf("ZF "); // 零标志
    if (eflags & (1 << 7))  printf("SF "); // 符号
    if (eflags & (1 << 11)) printf("OF "); // 溢出
    if (eflags & (1 << 10)) printf("DF "); // 方向
    if (eflags & (1 << 8))  printf("TF "); // 陷阱（单步）
    if (eflags & (1 << 9))  printf("IF "); // 中断使能
    printf("] (Value: 0x%08X)\n", eflags);
}

int CMyDebug::ShowRegisters()
{
    // 1. 获取当前发生异常/暂停的线程句柄
    // 注意：需要 THREAD_GET_CONTEXT 权限
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, m_DebugEvent.dwThreadId);
    if (!hThread)
    {
        printf("ShowRegisters: OpenThread failed (%d)\n", GetLastError());
        return 0;
    }

    // 2. 初始化 CONTEXT 结构体
    // 我们只需要获取寄存器信息，所以设置 CONTEXT_FULL (包含通用寄存器、段寄存器等)
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx))
    {
        printf("ShowRegisters: GetThreadContext failed (%d)\n", GetLastError());
        CloseHandle(hThread);
        return 0;
    }

    // 3. 格式化输出
    printf("\n--- Thread Context (TID: %d) ---\n", m_DebugEvent.dwThreadId);
    printf("EAX: 0x%08X   EBX: 0x%08X   ECX: 0x%08X   EDX: 0x%08X\n",
        ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx);
    printf("ESI: 0x%08X   EDI: 0x%08X   EBP: 0x%08X   ESP: 0x%08X\n",
        ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp);
    printf("EIP: 0x%08X   ", ctx.Eip);

    // 打印标志位
    PrintEFlags(ctx.EFlags);

    // 额外打印一些段寄存器信息 (可选)
    printf("CS: 0x%04X  DS: 0x%04X  SS: 0x%04X  ES: 0x%04X  FS: 0x%04X  GS: 0x%04X\n",
        ctx.SegCs, ctx.SegDs, ctx.SegSs, ctx.SegEs, ctx.SegFs, ctx.SegGs);
    printf("-------------------------------------------\n\n");

    CloseHandle(hThread);
    return 1;
}

void CMyDebug::DumpMemory(DWORD dwAddr, int length) {
    if (length <= 0) length = 64; // 默认显示64字节
    BYTE* buffer = new BYTE[length];
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(m_hProcess, (LPCVOID)dwAddr, buffer, length, &bytesRead)) {
        printf("DumpMemory: ReadProcessMemory failed (%d)\n", GetLastError());
        delete[] buffer;
        return;
    }

    printf("\nMemory Dump at 0x%08X:\n", dwAddr);
    printf("--------------------------------------------------------------------------\n");
    for (int i = 0; i < (int)bytesRead; i += 16) {
        // 1. 打印地址
        printf("0x%08X: ", dwAddr + i);

        // 2. 打印十六进制内容
        for (int j = 0; j < 16; j++) {
            if (i + j < (int)bytesRead)
                printf("%02X ", buffer[i + j]);
            else
                printf("   ");
            if (j == 7) printf("- "); // 中间加个分隔符好看
        }

        // 3. 打印 ASCII
        printf("  ");
        for (int j = 0; j < 16; j++) {
            if (i + j < (int)bytesRead) {
                char c = buffer[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
        }
        printf("\n");
    }
    printf("--------------------------------------------------------------------------\n\n");
    delete[] buffer;
}
void CMyDebug::ShowStackTrace(int nMaxFrames)
{
    if (nMaxFrames <= 0) nMaxFrames = 20;

    // 获取当前线程的上下文（需要 EIP, EBP）
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, m_DebugEvent.dwThreadId);
    if (!hThread) {
        printf("StackTrace: Failed to open thread (error %d)\n", GetLastError());
        return;
    }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;   // 获取全部寄存器，以便查看 EBP/EIP/ESP
    if (!GetThreadContext(hThread, &ctx)) {
        printf("StackTrace: Failed to get thread context (error %d)\n", GetLastError());
        CloseHandle(hThread);
        return;
    }
    CloseHandle(hThread);

    DWORD dwEip = ctx.Eip;
    DWORD dwEbp = ctx.Ebp;

    printf("\nStack Trace (max %d frames):\n", nMaxFrames);
    printf("%-4s %-10s %-10s %-10s %s\n", "#", "EIP", "ReturnAddr", "Frame(EBP)", "Args");
    printf("---- ---------- ---------- ---------- --------------------------\n");

    int frame = 0;
    DWORD curEbp = dwEbp;
    DWORD retAddr = 0;
    DWORD args[4] = { 0 };

    // 第 0 帧：当前正在执行的函数
    // 返回地址在 [EBP+4]，参数从 [EBP+8] 开始（仅当 EBP 合法时）
    if (curEbp >= 0x10000 && curEbp <= 0x7FFEFFFF) {
        SIZE_T rb = 0;
        BOOL bReadRet = ReadProcessMemory(m_hProcess, (LPCVOID)(curEbp + 4), &retAddr, sizeof(DWORD), &rb);
        BOOL bValidRet = (bReadRet && rb == sizeof(DWORD));

        // 读取前 4 个参数
        for (int i = 0; i < 4; i++) {
            if (!ReadProcessMemory(m_hProcess, (LPCVOID)(curEbp + 8 + i * 4), &args[i], sizeof(DWORD), &rb) || rb != sizeof(DWORD))
                args[i] = 0;
        }

        printf("%-4d 0x%08X", frame, dwEip);
        if (bValidRet) {
            printf(" 0x%08X 0x%08X", retAddr, curEbp);
            for (int i = 0; i < 4; i++) printf(" 0x%08X", args[i]);
        }
        else {
            printf(" %-10s %-10s", "???", "???");
        }
        printf("\n");
        frame++;
    }
    else {
        // EBP 非法，无法继续回溯
        printf("%-4d 0x%08X %-10s %-10s\n", frame, dwEip, "(no frame)", "(no frame)");
        return;
    }

    // 后续帧：沿着 EBP 链向上回溯
    while (frame < nMaxFrames) {
        DWORD parentEbp = 0;
        SIZE_T rb = 0;

        // 读取 [curEbp] 得到父帧的 EBP
        if (!ReadProcessMemory(m_hProcess, (LPCVOID)curEbp, &parentEbp, sizeof(DWORD), &rb) || rb != sizeof(DWORD)) {
            printf("  (unwind failed at EBP=0x%08X)\n", curEbp);
            break;
        }

        // 终止条件：父帧 EBP 为 0，或地址非法，或不递增（防止死循环）
        if (parentEbp == 0 || parentEbp <= curEbp || parentEbp > 0x7FFEFFFF) {
            break;
        }

        // 读取返回地址 [parentEbp + 4]
        DWORD parentRet = 0;
        if (!ReadProcessMemory(m_hProcess, (LPCVOID)(parentEbp + 4), &parentRet, sizeof(DWORD), &rb) || rb != sizeof(DWORD)) {
            printf("  (failed to read ret addr at EBP=0x%08X)\n", parentEbp);
            break;
        }

        // 读取参数 [parentEbp + 8] ~ [parentEbp + 20]
        for (int i = 0; i < 4; i++) {
            if (!ReadProcessMemory(m_hProcess, (LPCVOID)(parentEbp + 8 + i * 4), &args[i], sizeof(DWORD), &rb) || rb != sizeof(DWORD))
                args[i] = 0;
        }

        printf("%-4d %-10s 0x%08X 0x%08X", frame, " ", parentRet, parentEbp);
        for (int i = 0; i < 4; i++) printf(" 0x%08X", args[i]);
        printf("\n");

        curEbp = parentEbp;
        frame++;
    }

    if (frame >= nMaxFrames) {
        printf("  (reached max frames limit)\n");
    }
    printf("\n");
}