# kernel-livepatch-agent 使用指南

## 项目简介

自动化 CVE 内核热补丁生命周期管理代理。输入 CVE 编号 → 自动完成补丁解析、构建、应用、验证 → 输出报告。

### 核心能力

- **CVE 检索**: 从 NVD、Linux CVE announce、Linux stable 自动定位修复 commit
- **补丁解析**: 结构化解析 diff，提取文件、hunk、函数、风险标签
- **kpatch 构建**: 调用 kpatch-build 生成 livepatch .ko 模块
- **失败归因**: 自动分类失败原因（patch_apply / compile / kpatch_limit / env_missing / verify）
- **自动改写**: 规则优先 + LLM 辅助，最多 5 轮自动重试
- **运行验证**: 目标 VM 加载/卸载验证 + dmesg 收集
- **报告输出**: 结构化 report.json + 事件日志

---

## 快速开始

### 环境要求

| 组件 | 版本/说明 |
|------|-----------|
| Python | 3.10+ |
| 目标内核 | Anolis OS ANCK 6.6.102-5.2.an23.x86_64 |
| 构建环境 | Fedora x86_64 / Anolis OS 23.4 container |
| 验证环境 | Anolis OS 23.4 VM |

### 1. 克隆仓库

```bash
git clone https://github.com/n1425362023/kernel-livepatch-agent.git
cd kernel-livepatch-agent
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
pip install -e .
```

### 3. 运行测试

```bash
python -m pytest tests/ -v
```

### 4. 运行完整流程

```bash
# CLI 入口
python -m agent -c <CVE编号> [-w <工作目录>] [-p <补丁路径>] [-m <目标虚拟机IP>]

# 示例
python -m agent -c CVE-2024-1234 -w /tmp/kp-work
python -m agent -c CVE-2024-5678 -w /tmp/kp-work -p /path/to/patch.diff
python -m agent -c CVE-2024-9999 -w /tmp/kp-work -m 192.168.1.100
```

### 5. 批量处理

```bash
# 创建 CVE 列表文件
echo -e "CVE-2024-1234\nCVE-2024-5678\nCVE-2024-9999" > cves.txt

# 批量运行
./run --cves cves.txt --workdir ./output
```

---

## CLI 参数说明

| 参数 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `-c CVE_ID` | ✅ | - | CVE 编号，如 `CVE-2024-1234` |
| `-w WORKDIR` | ❌ | `./work/<CVE>` | 工作目录 |
| `-p PATCH` | ❌ | 自动获取 | 本地补丁路径，不填则自动从 kernel.org/NVD 获取 |
| `-m VM_HOST` | ❌ | - | 远程测试虚拟机 IP，用于 verifier 验证 |
| `--cves FILE` | ❌ | - | CVE 列表文件（批量模式） |
| `--kernel-version` | ❌ | `6.6.102-5.2.an23.x86_64` | 目标内核版本 |

---

## 架构概览

```
CVE输入 → 解析 → 获取补丁 → 构建kpatch → 应用 → 验证 → 报告输出
  ↓        ↓        ↓         ↓        ↓      ↓        ↓
resolver  parser   fetcher  builder  apply  verifier  reporter
                    ↕ planner (状态机调度) ↕
              失败 → classifier → advisor → 重试/人工
```

### 状态机流转

```
fetch_patch → parse_patch → build_kpatch → apply_patch → verify_patch
      ↓           ↓            ↓             ↓             ↓
  获取补丁     解析diff    生成kpatch模块   加载补丁     验证效果
                                                        ↓
                                              ┌── success ──→ done
                                              │
                                              ├── failure ──→ classify_failure
                                              │                    ↓
                                              │              non-retryable? ──→ done (failed)
                                              │                    ↓ retryable
                                              │              rewrite_advisor
                                              │                    ↓
                                              └────── build_kpatch (重试, 最多5轮)
```

### 不可重试的失败类型

| 类别 | 说明 |
|------|------|
| `no_fentry` | 函数缺少 fentry 插桩点，无法 hook |
| `struct_abi_mismatch` | 结构体 ABI 发生变化 |
| `field_mismatch` | 结构体字段不匹配 |
| `symbol_not_found` | 符号在目标内核中不存在 |

---

## 输出产物

每个 CVE 工作目录下生成：

```
work/CVE-2024-XXXX/
├── state.json            # 状态机当前状态
├── metadata/
│   ├── cve_metadata.json # CVE 元数据（NVD）
│   └── candidate_commits.json  # 候选修复 commit
├── patches/
│   ├── original.patch    # 原始补丁
│   └── attempt_N.patch   # 第 N 轮改写补丁
├── logs/
│   ├── build_N.log       # 第 N 轮构建日志
│   └── verify_N.log      # 验证日志
├── artifacts/
│   └── livepatch.ko      # 编译产物
├── patch_ir.json         # 补丁解析结果
├── failure.json          # 失败分类记录（如有）
├── rewrite_plan.json     # 重写建议（如有）
├── attempt_N.json        # 第 N 轮尝试记录
├── verification.json     # 验证结果
├── events.json           # 全流程事件日志
└── report.json           # 最终报告 ← 给人类看
```

### report.json 结构

```json
{
  "cve_id": "CVE-2024-1234",
  "kernel_version": "6.6.102-5.2.an23.x86_64",
  "status": "success|failed|manual_required|skipped",
  "summary": "...",
  "events": [...],
  "patch_ir": {
    "files": [...],
    "functions": [...],
    "risk_tags": [...]
  },
  "attempts": [...],
  "artifact": {
    "path": "artifacts/livepatch.ko",
    "sha256": "..."
  },
  "verification": {
    "loaded": true,
    "unloaded": true,
    "dmesg_clean": true
  },
  "reproducibility": {
    "build_env": "Anolis OS 23.4 container",
    "vm_env": "Anolis OS 23.4 VM"
  }
}
```

### status 含义

| 状态 | 含义 |
|------|------|
| `success` | 构建成功且加载、卸载验证通过 |
| `failed` | 自动流程走完但无法产出可用模块 |
| `manual_required` | 继续自动尝试不安全或证据不足 |
| `skipped` | 输入无效或目标源码已包含修复 |

---

## Docker 部署

### 构建镜像

```bash
docker-compose build
```

### 开发环境（挂载源码，热重载）

```bash
docker-compose up agent-dev
```

### 生产运行（一次执行完退出）

```bash
docker-compose up agent-run --build
```

### 服务说明

| 服务 | 说明 |
|------|------|
| `agent` | 基础镜像，仅含运行时依赖 |
| `agent-dev` | 开发环境，挂载源码 + 测试工具 |
| `agent-run` | 生产运行，挂载 workdir 输出产物 |

---

## WSL2 / Linux VM 真实环境

在真实 Linux 环境中运行 kpatch-build 和模块加载：

```bash
# 执行安装脚本
bash setup_env.sh

# 脚本会安装：
# - kernel-devel / kernel-debuginfo
# - kpatch-build 工具链
# - gcc / make / rpm 工具
# - 目标内核源码树
```

### 注意事项

1. **kpatch 构建** 需要完整的内核源码树和 build 工具链（gcc、make、kpatch-build）
2. **补丁加载** 需要 root 权限（`kpatch load`）
3. **远程验证** 需要 SSH 免密登录到目标 VM
4. **NVD API** 有速率限制，大量 CVE 处理需加间隔

---

## 目录结构

```
kernel-livepatch-agent/
├── agent/                  # 核心代理代码
│   ├── __main__.py         # CLI 入口 + 编排器
│   ├── state.py            # 状态管理器
│   ├── planner.py          # 决策规划器
│   └── tools/              # 工具模块
│       ├── cve_resolver.py     # CVE 检索
│       ├── patch_fetcher.py    # 补丁获取
│       ├── patch_parser.py     # 补丁解析
│       ├── kpatch_builder.py   # kpatch 构建
│       ├── verifier.py         # 运行验证
│       ├── failure_classifier.py  # 失败归因
│       ├── rewrite_advisor.py   # 改写建议
│       └── reporter.py         # 报告生成
├── tests/                  # 测试用例
├── docs/                   # 文档
├── Dockerfile              # 容器镜像
├── docker-compose.yml      # 多服务编排
├── setup_env.sh            # 环境安装脚本
├── run                     # CLI 可执行入口
├── requirements.txt        # Python 依赖
└── README.md               # 详细设计文档
```

---

## 设计原则

1. **规则优先，LLM 辅助**: 确定性错误由规则处理，复杂场景由 LLM 辅助
2. **先闭环后智能**: 先打通本地 CLI，再接入 MCP/HTTP 服务
3. **证据落盘**: 所有关键决策写入 JSON，终端输出仅作观察
4. **失败是有效结果**: 不可热补丁化、证据不足等情况清晰报告
5. **每个 CVE 独立执行**: 工作目录、状态机、日志、产物互相隔离

---

## 常见问题

### Q: 构建一直失败怎么办？

检查 `failure.json` 中的 `category` 和 `reason_code`。如果是 `env_missing`，运行 `setup_env.sh` 安装依赖。如果是 `kpatch_limit`，说明该 CVE 不适合 livepatch。

### Q: 如何查看某轮构建的完整日志？

查看 `work/CVE-XXXX/logs/build_N.log`，N 为尝试轮次。

### Q: 如何判断是否需要人工介入？

`report.json` 中 `status` 为 `manual_required` 时，查看 `failure.json` 中的 `manual_required_reason`。

### Q: 支持哪些目标内核？

默认支持 Anolis OS ANCK `6.6.102-5.2.an23.x86_64`，可通过 `--kernel-version` 指定其他版本。
