#include "CThreadManager.h"

CThreadManager::CThreadManager() {}
CThreadManager::~CThreadManager() { Clear(); }

void CThreadManager::AddThread(DWORD dwThreadId) {
    for (size_t i = 0; i < m_ThreadList.size(); i++) {
        if (m_ThreadList[i] == dwThreadId) return;
    }
    m_ThreadList.push_back(dwThreadId);
}

void CThreadManager::RemoveThread(DWORD dwThreadId) {
    for (auto it = m_ThreadList.begin(); it != m_ThreadList.end(); ++it) {
        if (*it == dwThreadId) {
            m_ThreadList.erase(it);
            break;
        }
    }
}

const std::vector<DWORD>& CThreadManager::GetThreads() const {
    return m_ThreadList;
}

void CThreadManager::Clear() {
    m_ThreadList.clear();
}