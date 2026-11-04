<p align="center">
  <img src="assets/jimothy.svg" width="180" alt="Jimothy，larpcop 的吉祥物：一只戴警帽、圆滚滚的浣熊">
</p>

<h1 align="center">larpcop</h1>

<p align="center">
  <b>你的 Agent 说“搞定了，测试全过”。larpcop 说：口说无凭，请出示凭证。</b>
</p>

<p align="center">
  <a href="https://github.com/NoahDuongMaster/larpcop/actions/workflows/ci.yml"><img src="https://github.com/NoahDuongMaster/larpcop/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/NoahDuongMaster/larpcop/releases/latest"><img src="https://img.shields.io/github/v/release/NoahDuongMaster/larpcop" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License: MIT OR Apache-2.0">
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.vi.md">Tiếng Việt</a> · <b>简体中文</b>
</p>

> **larp** /lɑːrp/ *（动词，2026 年网络用语）*：本义是 live-action role-playing（真人角色扮演），现指把自己根本没做过的事演得像真的一样。
> *“我遵守了规则，也跑了测试。”*（没跑，全靠演技。）

larpcop 让每个编程 Agent（coding agent：Claude Code、Codex、Gemini CLI、Cursor、Copilot CLI、Factory Droid、Kiro）和每个人类开发者都遵守同一套规则，不限技术栈。整个工具就是一个 Rust 二进制文件。规则用 [ast-grep](https://ast-grep.github.io)（基于 tree-sitter，支持 25+ 种语言）匹配，所以每次运行的判定都一样。关卡里没有模型，退出码里没有玄学。

吉祥物是 Jimothy，2026 年七月在西雅图走红的那只圆滚滚的浣熊，这里给它重新画了一顶警帽。

## 效果演示

Agent 写了一个文件，larpcop 在编辑完成后立刻检查，把错误发回给 Agent：

```text
larpcop: the file you just edited breaks enforced rules. Fix them now.

src/app.ts
  1:1     error   secrets  Found a Stripe Access Token ... (gitleaks rule `stripe-access-token`)
          │ const API_KEY="***";
          └ fix: Remove it from the code and load it from the environment or a secret manager.
  2:24    error   no-explicit-any  `any` disables type checking.
          │ export function run(x: any) {
          └ fix: Use a precise type, a generic, or `unknown` narrowed with a type guard or schema.
  4:3     error   no-suppression-comment  Suppression comment: it hides a check instead of fixing what it found.
          │ // @ts-ignore
  5:10    error   no-eval  `eval` / `new Function` executes strings as code.
          │ return eval(x);
```

接着 Agent 试了那个经典操作：

```text
$ git commit --no-verify -m "it works, trust me"
larpcop: blocked: skipping git hooks (`--no-verify` / `git commit -n`) is not allowed.
```

两段输出都来自 v0.3.0 的 release 二进制文件，为控制篇幅做过删减。

## 为什么用关卡，而不是提示词

提示词只能请求，只有确定性的检查才能拒绝。所以 larpcop 守在每个 Agent 都必须经过的几个节点上：

| 层级 | 运行内容 | Agent 能跳过吗？ |
|---|---|---|
| CI（[`enforce.yml`](.github/workflows/enforce.yml) 或组织级 ruleset） | `larpcop check --since origin/<base>` | 不能 |
| Git pre-commit（`larpcop install`） | `larpcop check --staged`（检查暂存区的内容，不是工作区） | 能，加 `--no-verify` 即可，之后由 CI 兜底 |
| Agent hook（`larpcop hook <agent>`） | 拦截绕过手段，每次编辑后立即报告错误，还有错误时不让 Agent 收工 | 没有 hook 的 Agent 会跳过它，但仍然会撞上 git 和 CI |
| `AGENTS.md`（`larpcop sync`） | 生成的开发规范和规则表 | 能，它只是建议 |

hook 负责缩短反馈周期，让规则真正有约束力的是 git 和 CI。详见[强制执行模型](docs/agents.md)。

## 安装

每个 release 都附带 macOS（arm64、x64）、Linux（arm64、x64）和 Windows（x64）的二进制文件，压缩后 5 到 9 MB。

```sh
# macOS and Linux
curl -LsSf https://github.com/NoahDuongMaster/larpcop/releases/latest/download/larpcop-installer.sh | sh
```

```powershell
# Windows
powershell -ExecutionPolicy Bypass -c "irm https://github.com/NoahDuongMaster/larpcop/releases/latest/download/larpcop-installer.ps1 | iex"
```

安装脚本会把二进制文件放进 `~/.local/bin`。想从源码构建，克隆仓库后运行 `cargo build --release`。目前还没有 crates.io 或 npm 包，Homebrew formula 随 release 附带，但尚未发布。

## 快速开始

```sh
cd your-repo
cat > .larpcop.yaml <<'EOF'
extends:
  - https://github.com/NoahDuongMaster/larpcop.git#v0.3.0//standards/recommended
EOF
larpcop install   # git pre-commit hook
larpcop sync      # AGENTS.md plus hook files for every agent
larpcop check     # see what it finds
```

`recommended` 是本仓库维护的规则集（见下文）。公司可以把自己的规范放在单独的仓库里，按 tag 固定版本。仓库无法退出 CI 强制执行的规范，标记为 `locked` 的规则也不能被禁用或覆盖。详见[配置](docs/configuration.md)。

## 能抓到什么

- **匹配结构，不匹配字面**：规则是 ast-grep 模式。Codex 曾对第一版 `no-console` 规则上演“上有政策，下有对策”，用 `globalThis["console"]["log"](x)` 就绕了过去。现在规则匹配的是结构，提示信息还会告诉 Agent：换个写法再来一遍，照样算违规。详见[规则](docs/rules.md)。
- **跨函数、跨文件的注入**：taint 分析会沿着赋值、调用、import、回调和类字段，追踪数据从 source 流向 sink。99 条 taint 规则覆盖 SQL、shell、XSS、SSRF、路径穿越、开放重定向、反序列化等。详见 [Taint](docs/taint.md)。
- **密钥**：二进制文件内置了 222 个 [gitleaks](https://github.com/gitleaks/gitleaks) 检测器，命中的内容会脱敏后输出。详见[安全](docs/security.md)。
- **依赖**：已知的恶意软件和已知漏洞（OSV.dev）会被拦截，`recommended` 在 `high` 级别开启这项检查。另外两道关卡需要手动开启：新版本的最低发布时长（常用设置是 14 天），以及每个新增的直接依赖都要由人工批准。hook 会在 `npm i some-evil-package` 的安装脚本运行之前就把它拦下。详见[依赖](docs/dependencies.md)。
- **代码质量**：函数长度、圈复杂度、面向存量代码的 baseline、SARIF 和 GitLab 报告、单条 sticky PR 评论、LSP 服务器，还有 HTML 仪表盘。
- **模型审查，但绝不当关卡**：`larpcop review` 和 `larpcop learn` 调用你手头已有的 CLI（`claude -p`、`codex exec`、`gemini`、`ollama`），只发出警告。`learn` 能把用文字描述的规范转成确定性的规则。详见 [AI 审查](docs/ai-review.md)。
- **Agent 可以主动调用的工具**：`larpcop mcp` 给 Agent 提供 `rules_for`、`check_content`、`check`、`fix` 和 `explain_rule`，这样 Agent 在写入之前就能先检查草稿。
- **组织级推广**：`larpcop org setup <owner>` 给每个仓库各开一个 PR。`larpcop sync --managed` 写入机器级别的策略文件，用户关不掉。详见[组织](docs/organization.md)。

`recommended` 规则集包含 93 个 ast-grep 规则文件、99 条 taint 规则、6 条文本规则、密钥检测器和漏洞检查。

## 支持的 Agent

| Agent | 工具运行前 | 编辑后 | 想收工时 |
|---|---|---|---|
| Claude Code | 支持 | 支持 | 支持 |
| Codex | 支持 | 支持 | 支持 |
| Gemini CLI | 支持 | 支持 | 支持 |
| Cursor | 支持 | 支持 | 支持 |
| Copilot CLI | 支持 | 支持 | 支持 |
| Factory Droid | 支持 | 支持 | 支持 |
| Kiro | 支持，并且会检查即将写入的内容 | 不可用（Kiro 不会把 PostToolUse 的输出返回给模型） | 支持 |

stop hook 只拦截一次。如果 Agent 还是要停（比如要向人确认），就放行，但违规的代码依然无法 commit 或合并。

Claude Code 和 Codex 用真实的 Agent 跑过。Kiro 的 payload 录自真实的 `kiro-cli`，Cursor 的 payload 来自 `cursor-agent` 的源码。Gemini CLI、Copilot CLI 和 Factory Droid 按各厂商的 hook 参考文档实现，没有用真实的 Agent 跑过。各 Agent 的详细说明见 [Agent](docs/agents.md)。

## 基准测试

检测对象是故意留有漏洞的项目，按各项目自带的已知漏洞清单打分。Semgrep OSS 使用 `p/default` 运行。

| 测试集 | larpcop | Semgrep OSS |
|---|---|---|
| Juice Shop，找到的漏洞代码行 | 11/27 | 6/27 |
| NodeGoat | 12/14 | 4/14 |
| DVNA | 12/14 | 7/14 |
| OWASP Benchmark Java（2,740 个用例，TPR − FPR） | +91.9% | +34.9% |
| NIST Juliet C#（1,443 个 web 用例，TPR − FPR） | +99.2% | +0.8% |
| NIST SARD PHP（20,856 个用例，TPR − FPR） | +56.4% | +0.1% |

看这些数字前要先说明一点：每个测试集首次运行时都是留出检验（held-out check），之后才被拿来写更多规则。首次运行的数字更低，和最终数字并排列在[基准测试](docs/benchmarks.md)里，同一页还有全部 22 个测试集、测试方法和漏掉的那些。可以用 `bench/run.sh` 重新跑一遍。

## 短板

- **逻辑漏洞和授权漏洞**（IDOR、缺少管理员权限校验、返回了过多数据）没有通用的语法形态。在其中三个基准测试集上，没有哪款 SAST 工具抓到过它们。`larpcop review` 瞄准的就是这类问题，但只能发出警告。
- **CSRF** 没有通用规则。一个会修改状态的 `GET` 处理函数，和正确的实现只差一次 token 校验，而“缺少某个调用”在每个文件里都成立。内置规则只抓明确关闭 CSRF 防护的写法，例如缺少 `protect_from_forgery` 的 Rails、Spring 的 `.disable()` 和 Django 的 `@csrf_exempt`。
- **Taint 分析只是近似**：它追踪什么、不追踪什么，列在 [Taint](docs/taint.md) 里。
- **基于安全公告的检查**无从得知还没有人上报的恶意版本。发布时长关卡（如果你开启了它）能补上其中的大部分缺口。
- **Agent 通过 shell 脚本写入的文件**是在命令执行之后才检查，而不是之前。pre-commit 和 CI 照常生效。

## 常见问题

**我的 Agent 直接传个 `--no-verify` 不就绕过去了？**
它大可以试试。hook 用真正的解析器读 shell 命令，所以 `bash -c 'rm .larpcop.yaml'`、`--no-ver""ify` 和 `sudo env SKIP=all git commit` 都会被拦下。就算有漏网的，CI 也会检查这个 PR。

**为什么不直接把规则写进 `AGENTS.md`，然后相信 Agent 会照做？**
Agent 读它的方式，和人读用户协议一样：拉到底，勾上“我已阅读并同意”。larpcop 确实会生成 `AGENTS.md`，因为它有用，但强制执行靠的不是它。

**会把我的代码发给模型吗？**
只有运行 `larpcop review` 或 `larpcop learn` 时才会，而且只发给你配置的那个 CLI。`check`、hook 和默认的 CI workflow 从不调用模型（workflow 里的 `review` 步骤默认关闭，除非你自己打开）。依赖检查会请求 deps.dev 和 OSV.dev。

**Jimothy 是谁？**
一只圆滚滚的浣熊，2026 年七月在西雅图大红大紫。现已持证上岗。

## 文档

以下参考文档目前只有英文版。

| 页面 | 内容 |
|---|---|
| [配置](docs/configuration.md) | 规范、`extends`、`locked`、命令、退出码、baseline、环境变量 |
| [规则](docs/rules.md) | 编写规则、`metadata.resolve`、修复与 fixture、`recommended` 规则集、质量报告 |
| [安全](docs/security.md) | 四个层级、文本规则、密钥 |
| [Taint](docs/taint.md) | `taint:` 参考、guard、类型感知的 sink、局限 |
| [依赖](docs/dependencies.md) | 审批、发布时长、漏洞与恶意软件 |
| [AI 审查](docs/ai-review.md) | `review` 和 `learn` |
| [Agent](docs/agents.md) | 强制执行模型、各 Agent 的 hook、MCP 服务器 |
| [组织](docs/organization.md) | 仪表盘、托管策略、`org`、CI workflow、release |
| [基准测试](docs/benchmarks.md) | 完整结果 |
| [验证](docs/verification.md) | 测试覆盖了什么，哪些是真实跑过的 |

## 开发

```sh
cargo fmt --check && cargo clippy --all-targets && cargo test
cargo run -- check   # larpcop checks its own source with its own rules
```

文件保持在 300 行以内，不吞错误，其余约定见仓库自己的 `AGENTS.md`。

## 许可证

本项目采用 [Apache-2.0](LICENSE-APACHE) 或 [MIT](LICENSE-MIT) 双许可，由你任选其一。

除非你另有明确声明，你有意提交并纳入 larpcop 的任何贡献（含义以 Apache-2.0 许可证中的定义为准），均按上述方式双许可，不附带任何额外条款或条件。

密钥检测器（`assets/gitleaks.toml`）来自 [gitleaks](https://github.com/gitleaks/gitleaks)，采用 MIT 许可证。许可证全文见 [`assets/gitleaks.LICENSE`](assets/gitleaks.LICENSE)。
