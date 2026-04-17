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
)

// tongsuoAvailable 检查Tongsuo库是否可用
func tongsuoAvailable() bool {
	tongsuoHome := os.Getenv("TONGSUO_HOME")
	if tongsuoHome == "" {
		return false
	}

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
