#include "CThreadManager.h"
#include <algorithm> // 引入标准算法库

CThreadManager::CThreadManager()
{
}

CThreadManager::~CThreadManager()
{
    Clear();
}

void CThreadManager::AddThread(DWORD dwThreadId)
{
    // 使用 std::find 替代手动循环，提升代码可读性与规范性
    if (std::find(m_ThreadList.begin(), m_ThreadList.end(), dwThreadId) == m_ThreadList.end())
    {
        m_ThreadList.push_back(dwThreadId);
    }
}

void CThreadManager::RemoveThread(DWORD dwThreadId)
{
    // 使用迭代器查找并安全擦除
    auto it = std::find(m_ThreadList.begin(), m_ThreadList.end(), dwThreadId);
    if (it != m_ThreadList.end())
    {
        m_ThreadList.erase(it);
    }
}

const std::vector<DWORD>& CThreadManager::GetThreads() const
{
    return m_ThreadList;
}

void CThreadManager::Clear()
{
    m_ThreadList.clear();
}