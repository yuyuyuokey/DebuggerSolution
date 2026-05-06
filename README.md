# DebuggerSolution

基于 MFC 的 Windows 用户态调试器，支持启动调试、附加进程、软件/硬件断点、反汇编、内存布局和调用堆栈查看。

## 项目结构

```
DebuggerSolution/
├── DebuggerEngine/          # 调试引擎 DLL
│   ├── DebuggerAPI.h/cpp    # 对外 C API 导出层
│   ├── CMyDebug.h/cpp       # 核心调试控制与事件循环
│   ├── CBreakpointManager.h/cpp  # 软/硬件断点管理
│   ├── CDisassembler.h/cpp  # 基于 Zydis 的反汇编引擎
│   └── CThreadManager.h/cpp # 被调试进程线程追踪
├── DebuggerGUI/             # MFC 前端界面
│   ├── DebuggerGUI.h/cpp    # 应用程序入口
│   ├── DebuggerGUIDlg.h/cpp # 主对话框（CPU/断点/内存/堆栈）
│   ├── CAIResultDlg.h/cpp   # AI 分析结果展示（QWENcoder）
│   ├── CBreakpointListDlg.h/cpp  # 断点列表管理
│   ├── CEditRegDlg.h/cpp    # 寄存器值编辑
│   └── CProcessListDlg.h/cpp # 进程选择（附加调试）
└── DebuggerSolution.slnx    # 解决方案文件
```

## 主要类职责

### 调试引擎（DebuggerEngine）

| 类 | 职责 |
|---|---|
| `CMyDebug` | 核心调试器。管理 `DEBUG_EVENT` 事件循环，处理进程创建/退出、线程创建/退出、DLL 加载/卸载、断点异常等调试事件；封装单步进入、单步步过、执行到返回、执行到用户代码等步进操作。 |
| `CBreakpointManager` | 断点管理器。软件断点通过 `INT3`（0xCC）替换原指令字节实现；硬件断点利用 x86 DR0-DR3 调试寄存器，支持执行/写入/访问三种类型。 |
| `CDisassembler` | 反汇编引擎。封装 Zydis 库，在调试启动时一次性反汇编整个 `.text` 段并缓存，供 UI 快速翻阅；支持按地址查找指令、判断 call 指令等辅助功能。 |
| `CThreadManager` | 轻量级线程追踪。维护当前被调试进程中所有活动线程的 ID 列表，供硬件断点等需要遍历线程的操作使用。 |

### GUI 界面（DebuggerGUI）

| 类 | 职责 |
|---|---|
| `CDebuggerGUApp` | MFC 应用程序入口，初始化主窗口。 |
| `CDebuggerGUIDlg` | 主调试窗口。集成反汇编视图、寄存器面板、内存 dump、堆栈视图；通过 Tab 切换断点列表/内存布局/调用堆栈面板；提供调试工具栏（运行、暂停、步入、步过等）和命令行输入；支持面板拖拽分割。 |
| `CAIResultDlg` | AI 分析结果弹窗。在后台线程调用 QWENcoder 分析当前汇编代码，以 RichEdit 展示分析结论。 |
| `CBreakpointListDlg` | 断点管理弹窗，展示和删除所有已设断点。 |
| `CEditRegDlg` | 寄存器编辑弹窗，允许直接修改寄存器值。 |
| `CProcessListDlg` | 进程列表弹窗，枚举系统进程供用户选择附加调试目标。 |

## 架构概览

```
┌─────────────────────────────────┐
│        DebuggerGUI (MFC)        │
│  CDebuggerGUIDlg  CAIResultDlg │
│  CBreakpointListDlg  ...       │
└──────────┬──────────────────────┘
           │ 调用 C API (dbg_*)
┌──────────▼──────────────────────┐
│    DebuggerEngine (DLL)         │
│  DebuggerAPI  ── 导出层        │
│  CMyDebug     ── 调试核心      │
│  CBreakpointManager ── 断点    │
│  CDisassembler ── 反汇编       │
│  CThreadManager ── 线程追踪    │
└──────────┬──────────────────────┘
           │ Win32 Debug API
┌──────────▼──────────────────────┐
│      被调试进程 (Target)        │
└─────────────────────────────────┘
```

GUI 通过回调（`DEBUG_EVENT_CALLBACK`）接收引擎的暂停/退出通知，引擎则通过 Win32 Debug API（`WaitForDebugEvent`/`ContinueDebugEvent`）接管目标进程的调试控制权。

## 构建

- 使用 Visual Studio 打开 `DebuggerSolution.slnx`
- DebuggerEngine 编译为 DLL，DebuggerGUI 编译为 MFC 可执行文件
- 依赖：Zydis（反汇编）、MFC 框架
