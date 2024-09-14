# 使用 Ubuntu 24.04 作为基础镜像
FROM --platform=$BUILDPLATFORM ubuntu:24.04 AS builder

# 避免交互式前端
ENV DEBIAN_FRONTEND=noninteractive

# 更新包列表并安装必要的工具
RUN apt-get update && apt-get install -y \
    golang-1.22 \
    git \
    make \
    gcc \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*

# 设置 Go 环境变量
ENV PATH="/usr/lib/go-1.22/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# 设置工作目录
WORKDIR /app

# 复制 go mod 和 sum 文件
COPY go.mod go.sum ./

# 设置构建参数
ARG TARGETARCH
ARG TARGETOS

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

RUN mkdir -p /app/internal/binary/

# 编译应用
RUN make build GOARCH=$TARGETARCH GOOS=$TARGETOS

# 使用 Ubuntu 24.04 作为最终镜像
FROM ubuntu:24.04

# 安装必要的运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root/

# 从 builder 阶段复制编译好的二进制文件
COPY --from=builder /app/cmd/nfs-trace .

# 暴露应用端口（如果需要的话）
# EXPOSE 8080

# 运行应用
CMD ["./cmd/nfs-trace"]
