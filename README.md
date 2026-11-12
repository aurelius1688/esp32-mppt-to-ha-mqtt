# MPPT to HA — ESP32 MPPT MQTT Bridge

将 ESP32 MPPT 太阳能控制器的数据通过 MQTT 接入 Home Assistant，并附带一个功能完整、界面精美的实时 Web 仪表盘。

## ✨ 核心功能

- **现代化 Web 仪表盘**：玻璃拟态 UI，支持亮/暗主题切换，基于 SSE 实时推送数据。
- **丰富的图表展示**：包含今日趋势曲线（支持 1/6/12/24 小时窗口，Y 轴自适应缩放）及近 7/30 天发电量柱状图。
- **天气实况联动**：接入中国天气网接口，根据天气状况（晴、雨、雪）和昼夜时间，动态切换 UI 天气图标。
- **双 CSV 格式自适应**：完美兼容标准 27 字段（standard）与青菜 26 字段（qingcai）固件。
- **Home Assistant 深度集成**：
  - 支持 MQTT 自动发现（Auto Discovery），自动生成传感器和实体。
  - 包含设备离线检测（LWT 遗嘱消息），实体掉线自动变灰。
  - 支持在 HA 中一键重启 ESP32（带有随机 Payload 防伪造机制）。
  - 发电量支持 `total_increasing`，完美接入 HA 能源面板。
- **企业级安全加固**：
  - 首次启动自动生成高强度随机管理员密码，强制用户修改。
  - 敏感信息采用 AES-256-GCM 加密存储，密钥独立文件保护。
  - 登录防爆破限流（IP 连错封禁），防时序攻击对比，防 SSRF 内网探测。
- **跨平台部署**：完美支持 Docker / NAS 部署，同时支持一键打包为 Windows `.exe` 独立运行。

## 🚀 快速开始

### 方式一：源码直接运行 (Node.js)

```bash
# 1. 安装依赖
npm install

# 2. 启动服务
node server.js
```
启动后，控制台会打印出 **首次启动的随机管理员密码**，请务必复制保存。
浏览器访问：`http://localhost:18080`

### 方式二：打包为 Windows 单文件 (.exe)

```bash
# 安装依赖与打包工具
npm install

# 执行打包命令
npm run build
```
打包完成后，当前目录会生成 `mppt-bridge.exe`。双击即可直接运行，无需安装 Node.js。

## ⚙️ Web 配置指南

打开网页后，点击右上角 **齿轮图标** 进行登录并配置：
- **ESP32 设备**：填入控制器的 IP 地址与认证信息。
- **MQTT 服务器**：填入 Broker 地址、端口及账号密码。
- **状态主题**：默认 `mppt/status`（HA 读取此主题）。
- **天气城市**：填入中国天气网的 9 位城市代码，留空则不显示天气。
- **轮询间隔**：建议 1000 - 5000 毫秒。

所有配置将自动加密保存至 `data/config.json`。

## 🏠 Home Assistant 集成

1. 在 HA 中确保已配置并启用了 **MQTT 集成**。
2. 启动本程序并连接 MQTT 后，HA 会自动发现名为 `ESP32 MPPT 控制器` 的设备。
3. 你将看到电压、电流、功率、今日/累计发电量等全套传感器，以及一个用于重启 ESP32 的按钮实体。

*注：若使用手动配置，可参考根目录下的 `ha_config.yaml`（如未使用自动发现）。*

## 📁 文件结构

```text
├── server.js          # 主程序（已包含全部安全加固逻辑）
├── package.json       # 依赖配置及打包脚本
├── public/            
│   └── index.html     # Web 仪表盘前端代码
├── data/              # (自动生成) 存放配置文件、历史电量与加密密钥
├── deploy-debian.md   # Debian / NAS 详细部署指南
└── .gitignore         # Git 忽略配置
```

## 🔧 环境变量支持 (可选)

如果你使用 Docker 或通过脚本拉起，支持使用环境变量覆盖默认配置：
- `PORT`：Web 服务端口 (默认 18080)
- `ESP32_URL` / `ESP32_USER` / `ESP32_PASS`：控制器地址
- `MQTT_URL` / `MQTT_USER` / `MQTT_PASS`：MQTT 服务地址
- `ADMIN_PASSWORD`：强制指定管理员密码（跳过随机生成）

## 📄 开源协议

基于 MIT License 协议开源。修改或分发请保留原作者信息。
