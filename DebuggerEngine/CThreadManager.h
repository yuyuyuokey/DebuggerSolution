#pragma once
#include <Windows.h>
#include <vector>

class CThreadManager
{
public:
    CThreadManager();
    ~CThreadManager();

    void AddThread(DWORD dwThreadId);
    void RemoveThread(DWORD dwThreadId);
    void Clear();

    // 获取所有活动的线程ID，用于下发硬件断点等需要遍历线程的操作
    const std::vector<DWORD>& GetThreads() const;

private:
    std::vector<DWORD> m_ThreadList;
};