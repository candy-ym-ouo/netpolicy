# netpolicy

NetPolicy Validator 是一个网络策略验证服务，用于导入访问规则并执行覆盖、冲突、冗余和可达性分析，同时提供 REST API、异步任务和原生 Web 页面。

## 本地验证

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

## 运行

```bash
go run ./cmd/server -addr :8080 -store memory
```

持久化模式：

```bash
go run ./cmd/server -addr :8080 -store sqlite -db ./netpolicy.data.json
```

启动后访问 `http://localhost:8080`。

## Docker 打包

```bash
./build_benzhi_docker.sh netpolicy linux/amd64
./build_benzhi_docker.sh netpolicy linux/arm64
docker run -it netpolicy:latest
```

镜像保留完整 Go 工具链，可在容器内继续执行测试和构建命令。
