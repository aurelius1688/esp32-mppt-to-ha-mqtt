# MPPT to HA — ESP32 MPPT MQTT Bridge

将 ESP32 MPPT 太阳能控制器的数据通过 MQTT 接入 Home Assistant，并附带实时 Web 仪表盘。

**在线演示：** [mppt.ezdiy.top](https://mppt.ezdiy.top)

## 功能

- 从 ESP32 HTTP API 获取光伏数据（电压、电流、功率、效率等）
- 发布到 MQTT，Home Assistant 自动发现传感器
- 实时 Web 仪表盘（SSE 推送，含图表）
- 网页端配置 ESP32 地址和 MQTT 服务器
- 密码保护（scrypt 哈希 + AES-256-GCM 加密存储）

## 快速开始

```bash
npm install
node server.js
```

打开 http://localhost:4088

默认管理密码：`admin`（首次运行后请在网页上修改）

## Web 配置

齿轮图标 → 登录 → 设置：
- ESP32 设备地址
- MQTT 服务器地址/账号/密码
- 轮询间隔
- 管理密码

所有密码以 scrypt 哈希或 AES-256-GCM 加密存储于 `config.json`。

## Home Assistant 集成

MQTT 自动发现已启用，只需在 HA 中配置 MQTT 集成，传感器会自动出现。

## 部署到 Debian

参见 `deploy-debian.md`。

## 文件结构

```
├── server.js          # 主程序
├── package.json       # 依赖
├── public/index.html  # Web 仪表盘
├── ha_config.yaml     # HA 手动配置参考
├── deploy-debian.md   # Debian 部署指南
└── .gitignore
```