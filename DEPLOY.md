# uglink-nav 部署文档

把绿联（UGREENlink）NAS 上的 Web 应用做成一键登录的导航页，部署在 Cloudflare Workers 上。

核心思路：**服务端只负责"签发一次登录"，日常流量不经过 Cloudflare**。用户点导航图标 → Worker 调绿联接口拿到一次性票据 → 302 给浏览器 → 浏览器拿到 `ugreen-proxy-token` 后直连绿联中继。

---

## 0. 从零准备 Cloudflare 账号与权限

本文示例统一使用 `nav.example.com` 和占位 ID。请替换为自己的信息，不要将真实口令、Token、NAS 密码或账户信息提交到 Git。

### 0.1 注册并准备账号

1. 打开 [Cloudflare 注册页](https://dash.cloudflare.com/sign-up)，注册账号并验证邮箱。
2. 进入 [Cloudflare Dashboard](https://dash.cloudflare.com/)，开启账号二次验证。
3. 打开 **Workers 和 Pages**，按页面提示启用 Workers。免费套餐即可运行本项目。
4. 如果使用自定义域名，在 Dashboard 选择 **添加站点**，输入根域名 `example.com`，不是最终的 `nav.example.com`。
5. 按 Cloudflare 提示，到域名注册商处将两个 NS 记录改为 Cloudflare 分配的值，等待域名显示已激活。

不使用自定义域名时，可暂时跳过域名接入，按 4.3 节改用 `*.workers.dev`。

### 0.2 准备本地环境

安装 Node.js 22 或更高版本和 Git，然后检查：

```bash
node --version
git --version
```

下载并安装项目依赖：

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/uglink-nav.git
cd uglink-nav
npm install
```

### 0.3 选择 Cloudflare 授权方式

**方式 A：OAuth（推荐）**

直接执行 4.1 节的 `npx wrangler login`。浏览器打开 Cloudflare 授权页后，核对账号和权限再允许。Wrangler 将登录凭据保存在本机配置目录，不会写入项目。

```bash
npx wrangler whoami
```

看到当前账号邮箱和账户名称即表示登录成功，不要将完整账户输出粘贴到公开位置。

**方式 B：创建最小权限 API Token**

无法使用浏览器 OAuth 时：

1. 打开 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)。
2. 点击 **创建令牌 → 创建自定义令牌**。
3. 按下表授予必要权限，账户和区域范围按实际部署目标最小化选择：

| 资源类型 | 范围 | 权限 |
| --- | --- | --- |
| 账户 | 你的账户 | Workers Scripts：编辑 |
| 账户 | 你的账户 | Workers KV Storage：编辑 |
| 区域 | 目标域名 | Workers Routes：编辑 |

4. 创建后复制 Token。Token 通常只完整显示一次，不要截图分享。
5. 仅在当前终端会话设置环境变量。

macOS / Linux：

```bash
export CLOUDFLARE_API_TOKEN='替换为你的 Token'
```

Windows PowerShell：

```powershell
$env:CLOUDFLARE_API_TOKEN='替换为你的 Token'
```

不要把 Token 写进 `wrangler.jsonc`、`.dev.vars.example` 或仓库。使用完毕后可执行 `unset CLOUDFLARE_API_TOKEN`；PowerShell 使用 `Remove-Item Env:CLOUDFLARE_API_TOKEN`。

---

## 1. 工作原理

```
浏览器 ──① 打开导航页 / 点图标──▶ Worker（你的域名）
                                    │
                                    │ ② 服务端登录：discovery → verify/check →
                                    │    verify/login → gateway/proxy/dockerToken
                                    ▼
                                 ③ 拿到一次性 redirect_url
浏览器 ◀──④ 302 跳转───────────────┘
浏览器 ──⑤ 访问 app-<端口>-<别名>.<中继域> ──▶ 绿联中继
                                             │ 下发 ugreen-proxy-token
浏览器 ──⑥ 之后直连中继（带 cookie），不再经过 Worker
```

已实测的行为：

- `redirect_url` 里的 ticket **一次性**，第二次打开失效
- **不绑定客户端**：在一台设备签发、另一台设备（不同网络）打开可以直接登录
- 多设备会话**不互斥**
- cookie 有效期未精确测出，数小时内可用；过期后回导航页再点一次即可

因此 Worker 只在"需要新票据"的瞬间参与，CF 慢或被限速只影响这一下，不影响已登录的会话。

---

## 2. 前置条件

| 项 | 要求 |
|---|---|
| Cloudflare 账户 | 域名已托管在该账户（NS 已生效） |
| 域名 | 用一个子域，例如 `nav.example.com` |
| Node.js | 22.x（用于 wrangler） |
| 绿联 NAS | 已开启 UGREENlink 远程访问 |
| NAS 账号 | **不能开启二次验证**（当前实现无法提交 OTP，会报 `otp_required`） |

---

## 3. 目录结构

```
uglink-nav/
├── worker.js          # 全部服务端逻辑 + 页面
├── liquidglass.txt    # 液态玻璃库（@ybouane/liquidglass dist，文本模块）
├── wrangler.jsonc     # Worker 配置：KV 绑定、自定义域、txt 模块规则
├── package.json       # 开发、检查与部署命令
└── .dev.vars.example  # 本地变量示例，不含真实口令
```

`worker.js` 里几个关键部分：

| 位置 | 作用 |
|---|---|
| `md5Hex` / `parseRsaPublicKey` / `rsaEncryptPKCS1` | 手写 MD5 与 RSA PKCS#1 v1.5（WebCrypto 只支持 OAEP） |
| `resolveOrigin` | 通过 `api-*.ugnas.com` 发现中继域名 |
| `mint` | 完整登录链路，返回一次性 `redirect_url` |
| `sign` / `isAuthed` | 访问口令 + HMAC 签名 cookie（7 天） |
| `layout` / `navPage` / `settingsPage` | 液态玻璃页面 |
| `fetch` | 路由：`/`、`/settings`、`/go`、`/api/*`、`/liquidglass.js`、`/health` |

---

## 4. 部署步骤

### 4.1 登录 wrangler

```bash
cd uglink-nav
npx wrangler login
```

浏览器会弹出 Cloudflare 授权页，核对账号和权限后允许。凭据保存在本机 Wrangler 配置目录，后续部署不再需要登录。

> 也可以不用 OAuth，改用 `CLOUDFLARE_API_TOKEN` 环境变量（需要 Workers Scripts:Edit、Workers KV Storage:Edit 权限）。

### 4.2 创建 KV 命名空间

```bash
npx wrangler kv namespace create CONFIG
```

把输出的 `id` 填进 `wrangler.jsonc`：

```jsonc
"kv_namespaces": [
  { "binding": "CONFIG", "id": "替换成你的 KV id" }
]
```

### 4.3 绑定自定义域

修改 `wrangler.jsonc`：

```jsonc
"routes": [
  { "pattern": "nav.example.com", "custom_domain": true }
]
```

- 域名必须属于当前账户
- 该子域**不能已有 A/CNAME 记录**，否则绑定失败；已有的话先去 DNS 里删掉
- 不需要自己手动加解析，wrangler 部署时会自动创建

如果暂时使用 Workers 临时域名，删除整个 `routes` 数组，并在 `wrangler.jsonc` 中添加：

```jsonc
"workers_dev": true
```

部署后使用 Wrangler 输出的 `https://uglink-nav.<你的子域>.workers.dev` 访问。

### 4.4 部署

```bash
npm run check
npx wrangler deploy --dry-run
npm run deploy
```

成功后会输出：`Uploaded uglink-nav`、`Deployed uglink-nav triggers`、域名。

### 4.5 设置访问口令

```bash
npx wrangler@latest secret put ADMIN_KEY
```

输入一个足够长的随机口令。这个口令是整站的入口，**不要提交到仓库，也不要贴到聊天里**。它不是 NAS 密码。

后续可在网页的「设置 → 修改访问口令」中修改，需要输入原口令和两次新口令。新口令使用 PBKDF2-SHA256 哈希保存，修改后所有旧登录会话失效。`ADMIN_KEY` 仍用于会话签名和初始登录，不要删除或随意轮换。

### 4.6 首次配置

1. 浏览器打开 `https://nav.example.com`
2. 输入上一步的口令
3. 进「设置」，填：
   - **UGREENlink ID**：绿联远程访问的别名（与中继域名里那段一致）
   - **NAS 用户名 / 密码**：建议用专用低权限账号
4. 保存后回导航页，点「新增应用」：
   - **名称 / 端口**：端口填 NAS 本机实际服务端口，不是容器映射端口
   - **分类**：可选，用于首页筛选
   - **图标**：可选，支持 Emoji、HTTPS 图片 URL 和 `data:image/svg+xml,...`
5. 保存后点应用，在新标签页打开并验证一键登录

应用的增删改只在首页进行；设置页只负责 NAS 凭据和访问口令。

---

## 5. 验证清单

```bash
curl -s https://nav.example.com/health              # 应返回 ok
curl -o /dev/null -w '%{http_code}\n' \
  -X POST --data 'key=wrong' https://nav.example.com/login   # 应返回 403
curl -s https://nav.example.com/liquidglass.js | head -c 40  # 应返回 JS 代码
```

浏览器侧：

- 导航页出现玻璃效果（`#root` 带 `lg-ready` 类说明 WebGL 生效）
- 点图标 → 跳转到 `.../api/ugreen/auth?token=...` → 落到已登录的应用页
- 之后再直接访问该应用域名，应该免登录
- 首页可新增、编辑、删除、搜索和按分类筛选应用
- 保存 NAS 凭据后，已有应用仍然存在
- 修改访问口令后，旧口令和旧会话失效，新口令可登录

---

## 6. 更新与回滚

```bash
# 更新代码后
npm run check
npm run deploy

# 查看最近部署
npx wrangler deployments list
```

回滚：在 Cloudflare 后台 → Workers & Pages → uglink-nav → 部署记录，选择历史版本重新部署。

**更新界面不影响已配置的数据**，配置在 KV `CONFIG` 的 `config` 键里。

---

## 7. 数据、凭据与安全

| 内容 | 位置 |
|---|---|
| 应用列表、UGREENlink ID、用户名、密码 | KV `CONFIG`（明文 JSON） |
| 修改后的访问口令 | KV `auth-password`（PBKDF2 哈希与随机盐） |
| 登录会话版本 | KV `auth-version` |
| 初始口令与会话签名密钥 | Worker Secret `ADMIN_KEY` |
| 登录态 cookie | 用户浏览器（7 天，HttpOnly + Secure） |

注意：

- 能编辑这个 Worker 或读取该账户 KV 的人，等于能拿到 NAS 账号密码；Cloudflare 账户请开二次验证
- 导航页 = NAS 入口，`ADMIN_KEY` 必须足够强；签发接口已按 IP 限速（10 次/分钟）
- 想换口令：优先使用网页设置；修改后旧 cookie 会立即失效
- 建议 NAS 上单独建一个只用于此服务的低权限账号
- `.dev.vars`、`.dev.vars.*`、`.env*` 和 `.wrangler/` 已在 `.gitignore` 中排除，提交前仍应执行 `git diff --cached` 检查
- 若口令或 Token 泄露，立即撤销 Token、轮换相关密钥并检查 KV 和部署日志

### 本地开发

```bash
cp .dev.vars.example .dev.vars
npm install
npm run dev
```

将 `.dev.vars` 中的示例值改为本地测试口令。默认访问 `http://localhost:8787`，本地 KV 与线上 KV 隔离。

---

## 8. 常见问题

| 现象 | 原因与处理 |
|---|---|
| 签发报 `otp_required` / 「要求二次验证」 | 账号开了二次验证，当前实现不支持；换免 OTP 账号或关闭验证 |
| `UGREENlink 发现失败` | 别名写错，或 NAS 未开启远程访问 |
| `登录失败（code xxxx）` | 账号密码错误，或账号被风控/锁定 |
| `签发失败（code xxxx）` | `dockerToken` 接口异常，通常是端口不存在或中继会话失败 |
| 绑定域名失败 | 该子域已有 DNS 记录；或域名不在当前账户 |
| 玻璃效果没出现 | 浏览器不支持 WebGL；页面会自动回退到 CSS 毛玻璃。可检查 `/liquidglass.js` 是否 200 |
| 页面样式错乱 | 浏览器缓存了旧 HTML；强制刷新 |
| 修改口令时报错 | 部署包含 PBKDF2 100000 次迭代的最新代码后重试 |

---

## 9. 技术备注（给后续维护者）

1. **RSA 公钥格式**：`verify/check` 返回的 `x-rsa-token` 是 base64 编码的 PEM，但头部写的是 `-----BEGIN RSA PUBLIC KEY-----`，内容实际是 SubjectPublicKeyInfo。Node/OpenSSL 按标签解析会报 `wrong tag`，必须剥掉标签后按 SPKI 重新包装。代码见 `parseRsaPublicKey`。
2. **WebCrypto 限制**：只支持 RSA-OAEP，而绿联用 PKCS#1 v1.5，因此自行实现填充 + BigInt 模幂。
3. **MD5**：Workers 的 `crypto.subtle` 不支持 MD5，代码里内联了纯 JS 实现（用于 `UG-Client-Id` 和 `X-Ugreen-Security-Key`）。
4. **液态玻璃库**：`@ybouane/liquidglass` 要求玻璃元素是根节点的**直接子级**，因此页面结构是 `#root > .bg / .bar / .panel`，内容统一放在 `.inner`（`z-index:1`）避免被注入的 canvas 覆盖。库以文本模块（`liquidglass.txt` + wrangler `rules: Text`）打包，不依赖 CDN。
5. **限制**：只代理 HTTP(S) 的登录入口；大文件、长时间下载、WebSocket、媒体播放没有兼容性保证。
6. **票据模型**：一次性、不绑客户端。分享给他人时，用 `/api/mint` 签出的链接在有效期内可直接打开；打开即消耗。

---

## 10. 相关文件

- `worker.js`：全部逻辑与页面
- `liquidglass.txt`：液态玻璃库（MIT，作者 [@ybouane](https://github.com/ybouane/liquidglass)）
- `wrangler.jsonc`：部署配置
