# MPPT MQTT Bridge — Debian 部署指南

## 环境要求

- Debian 11 / 12
- Node.js 18+

## 1. 安装 Node.js

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs
node -v   # 确认版本 ≥ 18
```

## 2. 部署项目

```bash
# 创建目录
mkdir -p /opt/mppt-bridge
cd /opt/mppt-bridge

# 上传源码（server.js、package.json、public/）到当前目录
# 可以用 scp、rsync 或直接 git clone

# 安装依赖
npm install --production
```

## 3. 配置端口

```bash
# 方法一：环境变量（推荐）
export PORT=4088
node server.js

# 方法二：直接修改 server.js 第 4 行
# const PORT = process.env.PORT || 4088;
```

## 4. 创建 systemd 服务（开机自启）

```bash
sudo nano /etc/systemd/system/mppt-bridge.service
```

粘贴以下内容：

```ini
[Unit]
Description=MPPT MQTT Bridge
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mppt-bridge
ExecStart=/usr/bin/node /opt/mppt-bridge/server.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production
Environment=PORT=4088

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable mppt-bridge
sudo systemctl start mppt-bridge
```

## 5. 管理服务

```bash
# 查看状态
sudo systemctl status mppt-bridge

# 查看日志
sudo journalctl -u mppt-bridge -f

# 重启
sudo systemctl restart mppt-bridge

# 停止
sudo systemctl stop mppt-bridge
```

## 6. 验证

```bash
curl http://localhost:4088/api/settings
```

正常返回 JSON 即部署成功。

## 7. 配置防火墙（可选）

```bash
# 仅内网访问
sudo ufw allow from 192.168.0.0/16 to any port 4088

# 如需外网访问（配合 Cloudflare Tunnel）
sudo ufw allow 4088
```

## 8. 文件结构

```
/opt/mppt-bridge/
├── server.js          # 主程序
├── package.json       # 依赖声明
├── config.json        # 运行时配置（自动生成）
├── ha_config.yaml     # HA 配置参考（无需部署）
├── node_modules/      # npm install 生成
└── public/
    └── index.html     # Web 仪表盘
```

首次启动后访问 `http://服务器IP:4088`，点击齿轮图标配置 ESP32 地址和 MQTT 参数即可。