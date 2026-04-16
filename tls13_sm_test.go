package tongsuogo_test

import (
	"testing"

	tongsuogo "github.com/tongsuo-project/tongsuo-go-sdk"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
)

// TestTLS13_SM_CtxCreation 验证 TLS 1.3 + SM 上下文创建
func TestTLS13_SM_CtxCreation(t *testing.T) {
	t.Parallel()

	ctx, err := tongsuogo.NewTLS13SMCtx()
	if err != nil {
		t.Fatalf("NewTLS13SMCtx: %v", err)
	}
	_ = ctx
}

// TestTLS13_SM_CipherSuiteConstants 验证 SM 密码套件常量正确
func TestTLS13_SM_CipherSuiteConstants(t *testing.T) {
	t.Parallel()

	if tongsuogo.SM4GCMCipherSuite != "TLS_SM4_GCM_SM3" {
		t.Errorf("SM4GCMCipherSuite = %q, want TLS_SM4_GCM_SM3", tongsuogo.SM4GCMCipherSuite)
	}
	if tongsuogo.SM4CCMCipherSuite != "TLS_SM4_CCM_SM3" {
		t.Errorf("SM4CCMCipherSuite = %q, want TLS_SM4_CCM_SM3", tongsuogo.SM4CCMCipherSuite)
	}
	if tongsuogo.SM2CurveID != 41 {
		t.Errorf("SM2CurveID = %d, want 41", tongsuogo.SM2CurveID)
	}
}

// TestTLS13_SM_SetCipherSuites 验证 TLS 1.3 上下文可以设置 SM 密码套件
func TestTLS13_SM_SetCipherSuites(t *testing.T) {
	t.Parallel()

	ctx, err := tongsuogo.NewCtxWithVersion(tongsuogo.TLSv1_3)
	if err != nil {
		t.Fatal(err)
	}

	// 测试单独设置 GCM
	if err := ctx.SetCipherSuites(tongsuogo.SM4GCMCipherSuite); err != nil {
		t.Fatalf("SetCipherSuites SM4_GCM_SM3: %v", err)
	}

	// 测试单独设置 CCM
	if err := ctx.SetCipherSuites(tongsuogo.SM4CCMCipherSuite); err != nil {
		t.Fatalf("SetCipherSuites SM4_CCM_SM3: %v", err)
	}

	// 测试设置全部 SM 套件
	if err := ctx.SetCipherSuites(tongsuogo.SMCipherSuites); err != nil {
		t.Fatalf("SetCipherSuites SMCipherSuites: %v", err)
	}
}

// TestTLS13_SM_WithSM2Key 验证 TLS 1.3 SM 上下文加载 SM2 密钥
func TestTLS13_SM_WithSM2Key(t *testing.T) {
	t.Parallel()

	ctx, err := tongsuogo.NewTLS13SMCtx()
	if err != nil {
		t.Fatal(err)
	}

	// 生成 SM2 密钥
	key, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	// 使用 SM2 私钥
	if err := ctx.UsePrivateKey(key); err != nil {
		t.Fatalf("UsePrivateKey SM2: %v", err)
	}
}

// TestTLS13_SM_MixedCipherSuites 验证 SM 与标准 TLS 1.3 密码套件可共存
func TestTLS13_SM_MixedCipherSuites(t *testing.T) {
	t.Parallel()

	ctx, err := tongsuogo.NewCtxWithVersion(tongsuogo.TLSv1_3)
	if err != nil {
		t.Fatal(err)
	}

	// 同时设置标准 + SM 密码套件
	mixed := "TLS_AES_256_GCM_SHA384:TLS_SM4_GCM_SM3:TLS_SM4_CCM_SM3"
	if err := ctx.SetCipherSuites(mixed); err != nil {
		t.Fatalf("SetCipherSuites mixed: %v", err)
	}
}
