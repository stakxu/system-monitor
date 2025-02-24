# 系统监控 API

## 编译和运行

确保已安装 Go 1.21 或更高版本：

1. 克隆或下载代码到本地
2. 进入项目目录
3. 安装依赖：
```bash
go mod tidy
```

4. 编译项目：
```bash
go build -o system-monitor
```

5. 运行程序：
```bash
./system-monitor
```

## 配置说明

配置文件为 `config.yaml`，包含以下配置项：

```yaml
# Server Configuration
server:
  port: 3000   
  listen:
    ipv4: true
    ipv6: true    
    private: false 
    public: true  

# Security Configuration
security:
  auth_token: "your-secure-token-here"
  max_retry: 3

# Process Monitoring Configuration
monitor:
  processes:
    - "mysql"
    - "nginx"
```

### 监听配置说明

- IPv4 + private: 监听 127.0.0.1
- IPv4 + public: 监听 0.0.0.0（将覆盖其他所有监听配置）
- IPv6 + private: 监听 [::1]
- IPv6 + public: 监听 [::]（将覆盖其他所有监听配置）

注意：
- 如果启用了 public 监听（0.0.0.0 或 [::]），其他监听配置将被忽略
- 建议只启用需要的监听选项，避免不必要的端口暴露

## API 调用示例

使用 curl 调用 API：

```bash
curl -H "Authorization: Bearer your-secure-token-here" http://localhost:3000/system-info
```

### 输出示例

```json
{
  "process": {
    "online": true,
    "uptime": 1234567
  },
  "system": {
    "architecture": "amd64",
    "platform": "linux",
    "release": "5.15.0-1039-azure",
    "distro": "ubuntu"
  },
  "memory": {
    "total": "16.00 GB",
    "free": "8.50 GB",
    "used": "7.50 GB",
    "usagePercentage": "46.88%"
  },
  "disk": {
    "total": "256.00 GB",
    "used": "128.00 GB",
    "free": "128.00 GB",
    "usagePercentage": "50.00%"
  },
  "cpu": {
    "model": "Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz",
    "cores": 12,
    "speed": "2.60 GHz",
    "load": "25.50%",
    "loadavg5": "1.15"
  },
  "network": {
    "uploadSpeed": "1.25 MB/s",
    "downloadSpeed": "2.50 MB/s",
    "totalUpload": "10.50 GB",
    "totalDownload": "25.75 GB"
  },
  "timestamp": {
    "current": "2023-11-15 14:30:45",
    "timezone": "CST"
  }
}
```

### 错误响应

如果认证失败，将返回 401 状态码：

```bash
# 没有提供令牌
curl http://localhost:3000/system-info
{"error": "未提供认证令牌"}

# 令牌无效
curl -H "Authorization: Bearer wrong-token" http://localhost:3000/system-info
{"error": "认证令牌无效"}
```
