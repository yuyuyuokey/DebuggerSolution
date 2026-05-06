#pragma once
#include <windows.h>

#ifdef AITOOLS_EXPORTS
#define AITOOLS_API __declspec(dllexport)
#else
#define AITOOLS_API __declspec(dllimport)
#endif

extern "C" {
    /// <summary>
    /// Initialize the AI Tools engine. Must be called after debugger is attached.
    /// </summary>
    /// <param name="hProcess">Handle to the target process (may be NULL).</param>
    /// <param name="pid">Target process ID.</param>
    /// <returns>true on success.</returns>
    AITOOLS_API bool InitAITools(HANDLE hProcess, DWORD pid);

    /// <summary>
    /// Universal tool dispatch bus.
    /// </summary>
    /// <param name="toolName">Name of the tool to execute (e.g. "read_assembly").</param>
    /// <param name="jsonArgs">JSON-formatted arguments string.</param>
    /// <param name="outResult">Pre-allocated buffer for the JSON result.</param>
    /// <param name="maxResultLen">Maximum length of outResult buffer.</param>
    /// <returns>1 on success, 0 on failure.</returns>
    AITOOLS_API int ExecuteAITool(const char* toolName, const char* jsonArgs, char* outResult, int maxResultLen);

    /// <summary>
    /// Update the current thread ID for register read context.
    /// Must be called before any tool that reads register state.
    /// </summary>
    AITOOLS_API void SetCurrentThreadId(DWORD threadId);
}
