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

package blackbox_tests

import (
	"os"
	"path/filepath"
	"runtime"
)

// tongsuoAvailable 检查Tongsuo库是否可用
func tongsuoAvailable() bool {
	// 检查环境变量
	tongsuoHome := os.Getenv("TONGSUO_HOME")
	if tongsuoHome == "" {
		return false
	}

	// 检查库文件是否存在
	libPath := filepath.Join(tongsuoHome, "lib")
	libFiles := []string{
		"libcrypto.so",
		"libcrypto.dylib",
		"libcrypto.a",
	}

	for _, libFile := range libFiles {
		if _, err := os.Stat(filepath.Join(libPath, libFile)); err == nil {
			return true
		}
	}

	return false
}

// isARM64 检查是否为ARM64架构
func isARM64() bool {
	return runtime.GOARCH == "arm64"
}

// isMacOS 检查是否为macOS
func isMacOS() bool {
	return runtime.GOOS == "darwin"
}

// skipIfTongsuoNotAvailable 如果Tongsuo不可用则跳过测试
func skipIfTongsuoNotAvailable(t testingT) {
	t.Helper()
	if !tongsuoAvailable() {
		t.Skip("Tongsuo not available - set TONGSUO_HOME environment variable")
	}
}

// skipIfARM64 如果是ARM64则跳过测试
func skipIfARM64(t testingT, reason string) {
	t.Helper()
	if isARM64() {
		skipReason := "ARM64 architecture"
		if reason != "" {
			skipReason += ": " + reason
		}
		t.Skip(skipReason)
	}
}

// testingT 测试接口，用于辅助函数
type testingT interface {
	Helper()
	Skip(args ...interface{})
	Skipf(format string, args ...interface{})
}
