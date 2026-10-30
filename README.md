# uglink-nav

部署在 Cloudflare Workers 上的绿联 NAS 应用导航页。点击应用时，Worker 通过保存的 NAS 账户在 UGREENlink 签发一次性登录票据，再由浏览器直接连接绿联中继，实现在手机端或者 PC 端免登录访问绿联 NAS 中的 Docker 应用。

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

- 管理员密码和 TOTP 密钥均保存在 Cloudflare KV 的配置 JSON 中。二者同等敏感，取得两者即可持续生成二次验证码。
- 自动签发需要将密码与 TOTP 密钥集中保存在 Worker 配置中，因此会削弱二次验证对“仅密码泄露”的隔离作用；请同时保护好 Cloudflare 账号及 Worker 部署权限。
- 请为 Cloudflare 账号开启强二次验证，不要提交 `.dev.vars`、API Token、NAS 密码、TOTP 密钥或二次验证二维码到 Git。

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
