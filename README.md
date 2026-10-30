# uglink-nav

部署在 Cloudflare Workers 上的绿联 NAS 应用导航页。点击应用时，Worker 通过保存的 NAS 账户在 UGREENlink 签发一次性登录票据，再由浏览器直接连接绿联中继，实现在手机端或者 PC 端免登录访问绿联 NAS 中的 Docker 应用。

> **重要安全警告：使用自动免登录，就意味着把绿联 NAS 管理员密码和 TOTP 二次验证密钥交给 Cloudflare 侧保存。**
>
> 当前版本将二者以配置 JSON 的形式保存在 Cloudflare KV 中，**不是“Worker 可以使用、但任何人都不可读”的存储方式**。拥有相应 Cloudflare 账号、API Token、KV 或 Worker 管理权限的人，可能读取凭据，或通过修改 Worker 获取凭据。
>
> **密码与 TOTP 密钥同时泄露后，攻击者可以持续生成二次验证码。此时，二次验证无法再保护你免受 Cloudflare 侧凭据泄露的影响。** 如果无法接受这一风险，请不要使用本项目，也不要将主要管理员账号的凭据保存到其中。部署前请务必阅读[凭据安全](#凭据安全)。

## 截图

![应用导航首页](docs/screenshot-home.png)

![新增 NAS 应用](docs/screenshot-add-app.png)

## 实现路径

![浏览器、Cloudflare Worker、KV 与绿联 NAS 的实现路径拓扑图](docs/topology-v2.png?v=2)

图中展示了配置读取、一次性登录票据签发，以及后续浏览器直连中继的完整链路。

## 功能

- 首页新增、编辑和删除 NAS 应用，配置持久化到 Cloudflare KV。
- 应用菜单可复制一次性登录链接，链接含临时凭据且打开后失效。
- 应用搜索、分类筛选、Emoji / HTTPS / SVG Data URL 图标。
- 应用在新标签页打开，保留 UGREENlink 一键登录流程。
- 独立 NAS 凭据设置，支持使用 TOTP 密钥自动完成绿联二次验证，可在浏览器本地解析二次验证二维码。
- 修改访问口令需验证原口令和两次新口令。
- 访问口令哈希存储，修改后使所有旧会话失效。
- 响应式液态玻璃界面，WebGL 不可用时自动回退。

## 快速开始

```bash
npm install
npx wrangler login
npx wrangler kv namespace create CONFIG
```

将 KV ID 和部署域名填入 `wrangler.jsonc`，然后：

```bash
npx wrangler secret put ADMIN_KEY
npm run deploy
```

完整的 Cloudflare 注册、权限、KV、域名和验证步骤见 [DEPLOY.md](DEPLOY.md)。

非 Docker 应用可通过 `marcnuri/port-forward` 容器中转端口后添加，具体配置见 [非 Docker 应用教程](DEPLOY.md#47-添加非-docker-应用通过-docker-中转端口)。

## NAS 账号与二次验证

绿联 NAS 的 Docker 应用访问需要**管理员账号**，普通用户不能用于本项目的应用登录与票据签发。建议使用仅供本服务使用的管理员账号，并在 NAS 上尽量开启二次验证，避免管理员密码泄露后被直接登录。

### 配置二次验证

1. 在绿联 NAS 的 **控制面板 → 安全性 → 账号安全 → 双重验证** 中开启二次验证。
2. 在绑定验证器的页面取得 Base32 TOTP 密钥。若只显示二维码，可保存二维码截图。
3. 打开本项目的 **设置**，填写 UGREENlink ID、管理员用户名和密码，然后选择一种方式填写密钥：
   - 将 Base32 密钥粘贴到 **TOTP 密钥（可选）**；
   - 点击 **从二维码读取密钥**，选择二维码截图。识别在浏览器本地完成，不会上传第三方服务或保存二维码图片。
4. 点击 **保存配置**，回到首页点击应用或复制一次性登录链接。

Worker 会在签发时使用保存的 TOTP 密钥自动生成 6 位动态验证码，并完成绿联二次验证；无需每次手动输入验证码。这里的 TOTP 密钥是绑定验证器时显示的固定密钥，不是验证器中不断变化的 6 位数字。

## 凭据安全

- **信任边界已经改变：** 使用本项目的自动免登录，不只是信任自己的 NAS 和浏览器，还必须信任 Cloudflare 账号及其 API Token、KV、Worker 的访问控制与部署流程。
- **凭据不是不可读机密：** 管理员密码和 TOTP 密钥保存在 Cloudflare KV 的配置 JSON 中，当前版本没有额外的应用层加密。即使改为 Worker Secret，也无法实现绝对意义上的“运行时可使用但部署者不可读”，因为 Worker 登录 NAS 时必须取得原始凭据。
- **TOTP 的防护范围会缩小：** 二次验证仍能防止“只有 NAS 密码泄露”的直接登录，但密码与 TOTP 密钥集中保存后，无法防止二者从同一位置一起泄露。取得两者即可持续生成有效的 6 位动态验证码。
- **管理员权限影响范围很大：** 绿联 Docker 应用访问要求管理员账号，该账号一旦失陷，影响可能不限于 Docker 应用。建议使用仅供本服务使用的独立管理员账号，但需要注意：独立管理员仍然拥有管理员权限，并不等于低权限账号。
- **保护 Cloudflare 控制面：** 为 Cloudflare 账号开启强二次验证，使用最小权限 API Token，定期轮换 Token 和 NAS 凭据，限制能够读取 KV、修改或部署 Worker 的人员与设备。
- **不要把秘密提交到 Git：** 不要提交 `.dev.vars`、API Token、NAS 密码、TOTP 密钥或二次验证二维码。二维码与 Base32 密钥具有相同的敏感性。
- **一次性链接也需要保密：** 一次性登录链接包含临时凭据，任何获得链接的人都可能在它失效前进入应用；不要公开发送、截图或粘贴到不可信服务。
- **不适合所有场景：** 如果 NAS 保存重要或敏感数据，且你无法承受云端管理员凭据泄露的后果，请不要使用自动免登录。更稳妥的方式是不在云端保存 NAS 管理员密码与 TOTP 密钥，改为每次手动登录。

## 本地开发

```bash
cp .dev.vars.example .dev.vars
npm install
npm run dev
```

编辑 `.dev.vars` 设置本地测试口令。该文件已被 Git 排除，不要提交真实凭据。

## 安全说明

二次验证二维码与 TOTP 密钥具有相同的敏感性。请仅在自己的设备上解析和保存，不要分享。

## License

MIT
