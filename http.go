// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tongsuogo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

const defaultReadHeaderTimeout = 120

// ListenAndServeTLS will take an http.Handler and serve it using OpenSSL over
// the given tcp address, configured to use the provided cert and key files.
func ListenAndServeTLS(addr string, certFile string, keyFile string,
	handler http.Handler,
) error {
	return ServerListenAndServeTLS(
		&http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: defaultReadHeaderTimeout * time.Second},
		certFile, keyFile)
}

// ServerListenAndServeTLS will take an http.Server and serve it using OpenSSL
// configured to use the provided cert and key files.
func ServerListenAndServeTLS(srv *http.Server,
	certFile, keyFile string,
) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	ctx, err := NewCtxFromFiles(certFile, keyFile)
	if err != nil {
		return err
	}

	l, err := Listen("tcp", addr, ctx)
	if err != nil {
		return err
	}

	err = srv.Serve(l)
	if err != nil {
		return fmt.Errorf("failed to serve tls: %w", err)
	}

	return nil
}

// Transport implements http.RoundTripper using Tongsuo TLS.
//
// 与 Go 标准库 net/http 默认的 TLS 实现不同，Transport 使用 Tongsuo
// 建立连接，支持国密 (SM2/SM3/SM4) 密码套件。
//
// 使用示例:
//
//	ctx, _ := ts.NewCtxFromFiles("client.crt", "client.key")
//	client := &http.Client{
//	    Transport: &ts.Transport{Ctx: ctx},
//	}
//	resp, err := client.Get("https://example.com")
//
// 注意:
//   - 不支持连接池（每次请求建立新连接）
//   - 不支持 HTTP/2
//   - 不自动使用系统根证书，需要通过 Ctx 配置
type Transport struct {
	// Ctx 是 TLS 上下文，必须设置。
	Ctx *Ctx

	// DialContext 可选的自定义拨号函数。
	// 如果为 nil，使用默认的 net.Dialer。
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (t *Transport) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if t.DialContext != nil {
		return t.DialContext(ctx, network, addr)
	}
	d := net.Dialer{}
	return d.DialContext(ctx, network, addr)
}

// RoundTrip 实现 http.RoundTripper 接口。
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Ctx == nil {
		return nil, errors.New("tongsuo: Transport.Ctx is nil")
	}

	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	// 建立 TCP 连接
	tcpConn, err := t.dial(req.Context(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tongsuo: dial %s: %w", addr, err)
	}

	// 包装为 Tongsuo TLS 连接
	conn, err := Client(tcpConn, t.Ctx)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("tongsuo: tls handshake: %w", err)
	}

	// 设置 SNI
	if err := conn.SetTLSExtHostName(host); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tongsuo: set hostname: %w", err)
	}

	// 完成握手
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tongsuo: handshake: %w", err)
	}

	// 用标准库发送请求（在 TLS 连接上）
	// clientConn 管理 Conn 的生命周期
	cc := &clientConn{Conn: conn, tcpConn: tcpConn}
	defer cc.Close()

	// 读写 HTTP 需要用裸连接
	// 标准 http 使用 bufio/httputil 更可靠
	return sendRequest(cc, req)
}

// clientConn 包装 Tongsuo Conn 使其满足 HTTP 传输需求
type clientConn struct {
	*Conn
	tcpConn net.Conn
}

func (c *clientConn) Close() error {
	return c.Conn.Close()
}

// sendRequest 在 TLS 连接上发送 HTTP 请求并读取响应
func sendRequest(conn net.Conn, req *http.Request) (*http.Response, error) {
	// 直接写 HTTP/1.1 请求
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("tongsuo: write request: %w", err)
	}

	// 读取响应
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, fmt.Errorf("tongsuo: read response: %w", err)
	}

	return resp, nil
}

// NewHTTPClient 创建使用 Tongsuo TLS 的 HTTP 客户端。
//
// 参数:
//   - ctx: Tongsuo SSL 上下文
func NewHTTPClient(ctx *Ctx) *http.Client {
	return &http.Client{
		Transport: &Transport{Ctx: ctx},
	}
}
