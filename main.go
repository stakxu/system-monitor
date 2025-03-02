package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
	psnet "github.com/shirou/gopsutil/v3/net"  // 使用别名避免冲突
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port   int `yaml:"port"`
		Listen struct {
			IPv4    bool `yaml:"ipv4"`
			IPv6    bool `yaml:"ipv6"`
			Private bool `yaml:"private"`
			Public  bool `yaml:"public"`
		} `yaml:"listen"`
	} `yaml:"server"`
	Security struct {
		AuthToken string `yaml:"auth_token"`
		MaxRetry  int    `yaml:"max_retry"`
	} `yaml:"security"`
	Monitor struct {
		Processes []string `yaml:"processes"`
	} `yaml:"monitor"`
}

var (
	config      Config
	lastRxBytes uint64
	lastTxBytes uint64
	lastCheck   time.Time
	rxSpeed     float64
	txSpeed     float64
	netLock     sync.Mutex
)

type SystemInfo struct {
    Process struct {
        Online    bool              `json:"online"`
        Uptime    float64           `json:"uptime"`
        Processes map[string]bool   `json:"processes"`  // 修改为map存储多个进程状态
    } `json:"process"`
    System struct {
        Architecture string `json:"architecture"`
        Platform     string `json:"platform"`
        Release      string `json:"release"`
        Distro       string `json:"distro"`
    } `json:"system"`
    Memory struct {
        Total           string `json:"total"`
        Free            string `json:"free"`
        Used            string `json:"used"`
        UsagePercentage string `json:"usagePercentage"`
    } `json:"memory"`
    Disk struct {
        Total           string `json:"total"`
        Used            string `json:"used"`
        Free            string `json:"free"`
        UsagePercentage string `json:"usagePercentage"`
    } `json:"disk"`
    CPU struct {
        Model      string `json:"model"`
        Cores      int    `json:"cores"`
        Speed      string `json:"speed"`
        Load       string `json:"load"`
        LoadAvg5   string `json:"loadavg5"`
    } `json:"cpu"`
    Network struct {
        UploadSpeed    string `json:"uploadSpeed"`
        DownloadSpeed  string `json:"downloadSpeed"`
        TotalUpload    string `json:"totalUpload"`
        TotalDownload  string `json:"totalDownload"`
    } `json:"network"`
    Connections int `json:"connections"` // 新增字段：网络链接数
    Timestamp struct {
        Current  string `json:"current"`
        Timezone string `json:"timezone"`
    } `json:"timestamp"`
}

func loadConfig() error {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	return nil
}

func getConnectionCount() (int, error) {
    // 获取所有网络连接
    conns, err := psnet.Connections("tcp")
    if err != nil {
        return 0, fmt.Errorf("获取网络连接数失败: %v", err)
    }
    return len(conns), nil
}

func getListenAddresses() []string {
	var addresses []string
	portStr := fmt.Sprintf(":%d", config.Server.Port)
	
	if config.Server.Listen.IPv4 {
		if config.Server.Listen.Private {
			addresses = append(addresses, "127.0.0.1"+portStr)
		}
		if config.Server.Listen.Public {
			addresses = append(addresses, "0.0.0.0"+portStr)
			return addresses // 如果监听 0.0.0.0，就不需要其他地址了
		}
	}
	
	if config.Server.Listen.IPv6 {
		if config.Server.Listen.Private {
			addresses = append(addresses, "[::1]"+portStr)
		}
		if config.Server.Listen.Public {
			addresses = append(addresses, "[::]"+portStr)
			return addresses // 如果监听 ::，就不需要其他地址了
		}
	}
	
	return addresses
}

func bytesToGB(bytes uint64) string {
	return fmt.Sprintf("%.2f GB", float64(bytes)/(1024*1024*1024))
}

func updateNetworkSpeeds() {
	for {
		netStats, err := psnet.IOCounters(false)  // 使用 psnet 别名
		if err != nil {
			log.Printf("获取网络统计信息失败: %v", err)
			time.Sleep(time.Second)
			continue
		}

		netLock.Lock()
		now := time.Now()
		if !lastCheck.IsZero() {
			timeDiff := now.Sub(lastCheck).Seconds()
			rxSpeed = float64(netStats[0].BytesRecv-lastRxBytes) / timeDiff / (1024 * 1024) // MB/s
			txSpeed = float64(netStats[0].BytesSent-lastTxBytes) / timeDiff / (1024 * 1024) // MB/s
		}
		lastRxBytes = netStats[0].BytesRecv
		lastTxBytes = netStats[0].BytesSent
		lastCheck = now
		netLock.Unlock()

		time.Sleep(time.Second)
	}
}

func withRetry(f func() error) error {
	var err error
	for i := 0; i < config.Security.MaxRetry; i++ {
		err = f()
		if err == nil {
			return nil
		}
		log.Printf("操作失败，正在进行第 %d 次重试: %v", i+1, err)
		time.Sleep(time.Second * time.Duration(i+1))
	}
	return fmt.Errorf("达到最大重试次数 (%d): %v", config.Security.MaxRetry, err)
}

func authenticateToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "未提供认证令牌", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token != config.Security.AuthToken {
			http.Error(w, "认证令牌无效", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// 检查指定程序是否运行中
func isProcessRunning(name string) bool {
	processes, err := process.Processes()
	if err != nil {
		log.Printf("获取进程列表失败: %v", err)
		return false
	}

	for _, p := range processes {
		n, err := p.Name()
		if err != nil {
			continue
		}
		if n == name {
			return true
		}
	}
	return false
}

func getSystemInfo(w http.ResponseWriter, r *http.Request) {
    var info SystemInfo
    info.Process.Online = true
    hostInfo, _ := host.Info()
    info.Process.Uptime = float64(hostInfo.Uptime)

    // 检查所有配置的进程状态
    info.Process.Processes = make(map[string]bool)
    for _, processName := range config.Monitor.Processes {
        info.Process.Processes[processName] = isProcessRunning(processName)
    }

    // 系统信息
    info.System.Architecture = runtime.GOARCH
    info.System.Platform = runtime.GOOS
    info.System.Release = hostInfo.PlatformVersion
    info.System.Distro = hostInfo.Platform

    // 内存信息
    err := withRetry(func() error {
        v, err := mem.VirtualMemory()
        if err != nil {
            return err
        }
        info.Memory.Total = bytesToGB(v.Total)
        info.Memory.Free = bytesToGB(v.Free)
        info.Memory.Used = bytesToGB(v.Used)
        info.Memory.UsagePercentage = fmt.Sprintf("%.2f%%", v.UsedPercent)
        return nil
    })
    if err != nil {
        log.Printf("获取内存信息失败: %v", err)
    }

    // 磁盘信息
    err = withRetry(func() error {
        d, err := disk.Usage("/")
        if err != nil {
            return err
        }
        info.Disk.Total = bytesToGB(d.Total)
        info.Disk.Used = bytesToGB(d.Used)
        info.Disk.Free = bytesToGB(d.Free)
        info.Disk.UsagePercentage = fmt.Sprintf("%.2f%%", d.UsedPercent)
        return nil
    })
    if err != nil {
        log.Printf("获取磁盘信息失败: %v", err)
    }

    // CPU信息
    err = withRetry(func() error {
        cpuInfo, err := cpu.Info()
        if err != nil {
            return err
        }
        percentage, err := cpu.Percent(time.Second, false)
        if err != nil {
            return err
        }
        loadavg, err := load.Avg()
        if err != nil {
            return err
        }

        if len(cpuInfo) > 0 {
            info.CPU.Model = cpuInfo[0].ModelName
            info.CPU.Cores = len(cpuInfo)
            info.CPU.Speed = fmt.Sprintf("%.2f GHz", cpuInfo[0].Mhz/1000)
        }
        if len(percentage) > 0 {
            info.CPU.Load = fmt.Sprintf("%.2f%%", percentage[0])
        }
        info.CPU.LoadAvg5 = fmt.Sprintf("%.2f", loadavg.Load5)
        return nil
    })
    if err != nil {
        log.Printf("获取CPU信息失败: %v", err)
    }

    // 网络信息
    netLock.Lock()
    info.Network.UploadSpeed = fmt.Sprintf("%.2f MB/s", txSpeed)
    info.Network.DownloadSpeed = fmt.Sprintf("%.2f MB/s", rxSpeed)
    info.Network.TotalUpload = bytesToGB(lastTxBytes)
    info.Network.TotalDownload = bytesToGB(lastRxBytes)
    netLock.Unlock()

    // 获取链接数
    connCount, err := getConnectionCount()
    if err != nil {
        log.Printf("获取链接数失败: %v", err)
    } else {
        info.Connections = connCount
    }

    // 时间信息（使用北京时间）
    loc, err := time.LoadLocation("Asia/Shanghai")
    if err != nil {
        log.Printf("加载北京时区失败: %v", err)
        loc = time.UTC // 如果加载失败，使用 UTC 作为备选
    }
    now := time.Now().In(loc) // 显式转换为北京时间
    info.Timestamp.Current = now.Format("2006-01-02 15:04:05")
    info.Timestamp.Timezone = loc.String() // 确保时区名称正确

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(info)
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	
	if err := loadConfig(); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	log.Printf("系统监控API正在启动")

	// 启动网络速度监控
	go updateNetworkSpeeds()

	http.HandleFunc("/system-info", authenticateToken(getSystemInfo))

	addresses := getListenAddresses()
	if len(addresses) == 0 {
		log.Fatal("未配置任何有效的监听地址")
	}

	log.Printf("API已启动，使用Authorization header和Bearer token访问API")
	log.Printf("示例: curl -H \"Authorization: Bearer %s\" http://localhost:%d/system-info", 
		config.Security.AuthToken, config.Server.Port)

	// 使用一个 server 实例来处理所有地址
	server := &http.Server{
		Handler: http.DefaultServeMux,
	}

	// 监听所有配置的地址
	for _, addr := range addresses {
		log.Printf("正在监听: %s", addr)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("监听地址 %s 失败: %v", addr, err)
			continue
		}
		go server.Serve(listener)
	}

	// 保持主程序运行
	select {}
}
