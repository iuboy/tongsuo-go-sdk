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

package crypto

// #include "shim.h"
import "C"

import (
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

// OCSP 证书状态常量，与 RFC 6960 Section 2.2 一致
const (
	OCSPStatusGood    = 0 // 证书状态正常
	OCSPStatusRevoked = 1 // 证书已撤销
	OCSPStatusUnknown = 2 // 证书状态未知
)

// OCSP 响应状态码，与 RFC 6960 Section 2.3 一致
const (
	OCSPResponseStatusSuccessful        = 0
	OCSPResponseStatusMalformedRequest  = 1
	OCSPResponseStatusInternalError     = 2
	OCSPResponseStatusTryLater          = 3
	OCSPResponseStatusSignatureRequired = 5
	OCSPResponseStatusUnauthorized      = 6
)

// 撤销原因常量，与 RFC 5280 Section 5.3.1 一致
const (
	OCSPReasonUnspecified          = 0
	OCSPReasonKeyCompromise        = 1
	OCSPReasonCACompromise         = 2
	OCSPReasonAffiliationChanged   = 3
	OCSPReasonSuperseded           = 4
	OCSPReasonCessationOfOperation = 5
	OCSPReasonCertificateHold      = 6
	OCSPReasonRemoveFromCRL        = 8
	OCSPReasonPrivilegeWithdrawn   = 9
	OCSPReasonAACompromise         = 10
)

// OCSPResponse 表示已解析的 OCSP 响应
type OCSPResponse struct {
	resp     *C.OCSP_RESPONSE
	Raw      []byte
	freeOnce sync.Once
}

// buildCertID 构建 OCSP 证书 ID（内部辅助函数）
//
// 提取自 CreateOCSPResponse 和 FindStatus 中的重复代码。
// 将 big.Int 序列号转换为 OCSP_CERTID，用于 OCSP 请求/响应匹配。
func buildCertID(issuer *C.X509, serial *big.Int) (*C.OCSP_CERTID, error) {
	serialBytes := serial.Bytes()
	serialASN1 := C.ASN1_INTEGER_new()
	if serialASN1 == nil {
		return nil, ErrMallocFailure
	}

	bn := C.BN_new()
	if bn == nil {
		C.ASN1_INTEGER_free(serialASN1)
		return nil, ErrMallocFailure
	}

	bn = C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&serialBytes[0])), C.int(len(serialBytes)), bn)
	if bn == nil {
		C.BN_free(bn)
		C.ASN1_INTEGER_free(serialASN1)
		return nil, fmt.Errorf("failed to convert serial to bignum: %w", PopError())
	}
	serialASN1 = C.BN_to_ASN1_INTEGER(bn, serialASN1)
	C.BN_free(bn)
	if serialASN1 == nil {
		return nil, fmt.Errorf("failed to convert serial to ASN1 integer: %w", PopError())
	}
	defer C.ASN1_INTEGER_free(serialASN1)

	subjectCert := C.X509_dup(issuer)
	if subjectCert == nil {
		return nil, fmt.Errorf("failed to duplicate issuer cert: %w", PopError())
	}
	defer C.X509_free(subjectCert)

	C.X509_set_serialNumber(subjectCert, serialASN1)

	cid := C.X_OCSP_cert_to_id(nil, subjectCert, issuer)
	if cid == nil {
		return nil, fmt.Errorf("failed to create OCSP cert ID: %w", PopError())
	}

	return cid, nil
}

// CreateOCSPResponse 创建 OCSP 响应并返回 DER 编码
//
// SM2 密钥签名时，Tongsuo 自动使用 SM3 摘要算法（符合 GM/T 0009-2012）。
// 其他密钥类型使用对应的标准摘要算法。
//
// 参数：
//
//	issuer:    颁发者 CA 证书（用于构建 CertID 和签名）
//	privKey:   签名私钥（SM2/RSA/ECDSA）
//	serial:    目标证书序列号
//	status:    证书状态（OCSPStatusGood/OCSPStatusRevoked/OCSPStatusUnknown）
//	thisUpdate: 此更新时间
//	nextUpdate: 下次更新时间（零值表示不设置）
//	revokedAt: 撤销时间（仅 status=OCSPStatusRevoked 时有效）
func CreateOCSPResponse(issuer *Certificate, privKey PrivateKey,
	serial *big.Int, status int, thisUpdate, nextUpdate time.Time,
	revokedAt time.Time) ([]byte, error) {

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if issuer == nil || issuer.x == nil {
		return nil, fmt.Errorf("issuer certificate is nil: %w", ErrNilParameter)
	}
	if privKey == nil {
		return nil, fmt.Errorf("private key is nil: %w", ErrNilParameter)
	}
	if serial == nil {
		return nil, fmt.Errorf("serial number is nil: %w", ErrNilParameter)
	}
	if serial.Sign() <= 0 {
		return nil, fmt.Errorf("serial number must be positive: %w", ErrNilParameter)
	}

	// 构建 OCSP 证书 ID
	cid, err := buildCertID(issuer.x, serial)
	if err != nil {
		return nil, err
	}
	defer C.OCSP_CERTID_free(cid)

	// 创建 BasicOCSPResponse
	bs := C.X_OCSP_BASICRESP_new()
	if bs == nil {
		return nil, fmt.Errorf("failed to create OCSP basic response: %w", PopError())
	}
	defer C.X_OCSP_BASICRESP_free(bs)

	// 转换时间
	thisASN1, err := timeToASN1(thisUpdate)
	if err != nil {
		return nil, fmt.Errorf("failed to convert thisUpdate: %w", err)
	}
	defer C.ASN1_TIME_free(thisASN1)

	var nextASN1 *C.ASN1_TIME
	if !nextUpdate.IsZero() {
		nextASN1, err = timeToASN1(nextUpdate)
		if err != nil {
			return nil, fmt.Errorf("failed to convert nextUpdate: %w", err)
		}
		defer C.ASN1_TIME_free(nextASN1)
	}

	var revASN1 *C.ASN1_TIME
	if status == OCSPStatusRevoked && !revokedAt.IsZero() {
		revASN1, err = timeToASN1(revokedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to convert revokedAt: %w", err)
		}
		defer C.ASN1_TIME_free(revASN1)
	}

	// 添加证书状态
	// X_OCSP_basic_add1_status 返回 OCSP_SINGLERESP*，nil 表示失败
	if C.X_OCSP_basic_add1_status(bs, cid, C.int(status), 0,
		revASN1, thisASN1, nextASN1) == nil {
		return nil, fmt.Errorf("failed to add OCSP status: %w", PopError())
	}

	// 签名 BasicOCSPResponse
	// dgst=NULL 让 Tongsuo 根据密钥类型自动选择摘要算法
	// SM2 密钥 → SM3, RSA/ECDSA → SHA256
	if C.X_OCSP_basic_sign(bs, issuer.x, privKey.EvpPKey(), nil, nil, 0) != 1 {
		return nil, fmt.Errorf("failed to sign OCSP response: %w", PopError())
	}

	// 创建完整的 OCSPResponse
	resp := C.X_OCSP_response_create(C.int(OCSPResponseStatusSuccessful), bs)
	if resp == nil {
		return nil, fmt.Errorf("failed to create OCSP response: %w", PopError())
	}
	defer C.X_OCSP_response_free(resp)

	return serializeOCSPResponseToDER(resp)
}

// ParseOCSPResponse 解析 DER 编码的 OCSP 响应
func ParseOCSPResponse(der []byte) (*OCSPResponse, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if len(der) == 0 {
		return nil, fmt.Errorf("empty OCSP response: %w", ErrNilParameter)
	}

	// 复制到 C 内存避免 CGo 指针规则问题
	derLen := len(der)
	derBuf := (*C.uchar)(C.malloc(C.size_t(derLen)))
	if derBuf == nil {
		return nil, ErrMallocFailure
	}
	defer C.free(unsafe.Pointer(derBuf))
	C.memcpy(unsafe.Pointer(derBuf), unsafe.Pointer(&der[0]), C.size_t(derLen))

	ppin := derBuf
	resp := C.X_d2i_OCSP_RESPONSE(nil, &ppin, C.long(derLen))
	if resp == nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %w", ErrOCSPResponseParse)
	}

	r := &OCSPResponse{
		resp: resp,
		Raw:  der,
	}
	runtime.SetFinalizer(r, (*OCSPResponse).free)

	return r, nil
}

// Free 手动释放 OCSP 响应的 C 资源
//
// 使用 sync.Once 防止 Finalizer 与手动 Free() 之间的 double-free 竞态。
// 调用 Free() 后，finalizer 会被清除，对象不可再使用。
func (r *OCSPResponse) Free() {
	r.freeOnce.Do(func() {
		if r.resp != nil {
			C.X_OCSP_response_free(r.resp)
			r.resp = nil
		}
		runtime.SetFinalizer(r, nil)
	})
}

// free 是内部释放方法，供 finalizer 和 Free() 共享
func (r *OCSPResponse) free() {
	r.freeOnce.Do(func() {
		if r.resp != nil {
			C.X_OCSP_response_free(r.resp)
			r.resp = nil
		}
	})
}

// GetStatus 返回 OCSP 响应状态码
func (r *OCSPResponse) GetStatus() int {
	return int(C.X_OCSP_response_status(r.resp))
}

// FindStatus 在 OCSP 响应中查找指定证书的状态
//
// 参数：
//
//	issuer: 颁发者证书（用于构建 CertID）
//	serial: 目标证书序列号
//
// 返回：
//
//	certStatus:      证书状态（OCSPStatusGood/OCSPStatusRevoked/OCSPStatusUnknown）
//	revocationReason: 撤销原因（仅 OCSPStatusRevoked 时有效）
//	thisUpdate:      此更新时间
//	nextUpdate:      下次更新时间
//	revokedAt:       撤销时间（仅 OCSPStatusRevoked 时有效）
//	err:             错误
func (r *OCSPResponse) FindStatus(issuer *Certificate, serial *big.Int) (
	certStatus int, revocationReason int,
	thisUpdate, nextUpdate, revokedAt time.Time, err error) {

	if r.resp == nil {
		return 0, 0, time.Time{}, time.Time{}, time.Time{},
			fmt.Errorf("OCSP response is nil: %w", ErrNilParameter)
	}
	if issuer == nil || issuer.x == nil {
		return 0, 0, time.Time{}, time.Time{}, time.Time{},
			fmt.Errorf("issuer certificate is nil: %w", ErrNilParameter)
	}
	if serial == nil {
		return 0, 0, time.Time{}, time.Time{}, time.Time{},
			fmt.Errorf("serial number is nil: %w", ErrNilParameter)
	}
	if serial.Sign() <= 0 {
		return 0, 0, time.Time{}, time.Time{}, time.Time{},
			fmt.Errorf("serial number must be positive: %w", ErrNilParameter)
	}

	// 获取 BasicOCSPResponse
	bs := C.X_OCSP_response_get1_basic(r.resp)
	if bs == nil {
		return 0, 0, time.Time{}, time.Time{}, time.Time{},
			fmt.Errorf("failed to get basic response: %w", ErrOCSPResponseParse)
	}
	defer C.X_OCSP_BASICRESP_free(bs)

	// 构建 OCSP 证书 ID
	cid, err := buildCertID(issuer.x, serial)
	if err != nil {
		return 0, 0, time.Time{}, time.Time{}, time.Time{}, err
	}
	defer C.OCSP_CERTID_free(cid)

	// 查找状态
	var cStatus, cReason C.int
	var cRevtime, cThisupd, cNextupd *C.ASN1_TIME

	if C.X_OCSP_resp_find_status(bs, cid, &cStatus, &cReason,
		&cRevtime, &cThisupd, &cNextupd) != 1 {
		return 0, 0, time.Time{}, time.Time{}, time.Time{},
			fmt.Errorf("certificate status not found: %w", ErrOCSPStatusNotFound)
	}

	certStatus = int(cStatus)
	revocationReason = int(cReason)
	thisUpdate, err = asn1ToTime(cThisupd)
	if err != nil {
		return 0, 0, time.Time{}, time.Time{}, time.Time{},
			fmt.Errorf("failed to parse thisUpdate: %w", err)
	}
	nextUpdate, err = asn1ToTime(cNextupd)
	if err != nil {
		return 0, 0, time.Time{}, time.Time{}, time.Time{},
			fmt.Errorf("failed to parse nextUpdate: %w", err)
	}
	revokedAt, err = asn1ToTime(cRevtime)
	if err != nil {
		return 0, 0, time.Time{}, time.Time{}, time.Time{},
			fmt.Errorf("failed to parse revokedAt: %w", err)
	}

	return certStatus, revocationReason, thisUpdate, nextUpdate, revokedAt, nil
}

// serializeOCSPResponseToDER 将 OCSP_RESPONSE 序列化为 DER 编码的字节切片
func serializeOCSPResponseToDER(resp *C.OCSP_RESPONSE) ([]byte, error) {
	derLen := C.X_i2d_OCSP_RESPONSE(resp, nil)
	if derLen <= 0 {
		return nil, fmt.Errorf("failed to get OCSP response DER length: %w", PopError())
	}

	derBuf := (*C.uchar)(C.malloc(C.size_t(derLen)))
	if derBuf == nil {
		return nil, ErrMallocFailure
	}
	defer C.free(unsafe.Pointer(derBuf))

	derPtr := derBuf
	if C.X_i2d_OCSP_RESPONSE(resp, &derPtr) != derLen {
		return nil, fmt.Errorf("failed to serialize OCSP response: %w", PopError())
	}

	return C.GoBytes(unsafe.Pointer(derBuf), C.int(derLen)), nil
}

// timeToASN1 将 time.Time 转换为 ASN1_TIME
// 使用 ASN1_TIME_set 设置绝对时间（非相对偏移）
func timeToASN1(t time.Time) (*C.ASN1_TIME, error) {
	result := C.ASN1_TIME_set(nil, C.time_t(t.Unix()))
	if result == nil {
		return nil, fmt.Errorf("ASN1_TIME_set failed: %w", PopError())
	}
	return result, nil
}

// asn1ToTime 将 ASN1_TIME 转换为 time.Time
//
// nil *C.ASN1_TIME 表示可选字段未设置，返回 (time.Time{}, nil)
// 非 nil 但解析失败返回 error，区分"可选字段未设置"和"解析出错"
func asn1ToTime(t *C.ASN1_TIME) (time.Time, error) {
	if t == nil {
		return time.Time{}, nil
	}

	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return time.Time{}, fmt.Errorf("BIO_new failed in asn1ToTime: %w", PopError())
	}
	defer C.BIO_free(bio)

	if C.ASN1_TIME_print(bio, t) != 1 {
		return time.Time{}, fmt.Errorf("ASN1_TIME_print failed: %w", PopError())
	}

	var ptr *C.char
	length := C.X_BIO_get_mem_data(bio, &ptr)
	if length <= 0 || ptr == nil {
		return time.Time{}, fmt.Errorf("failed to read ASN1_TIME string")
	}

	// ASN1_TIME_print 输出格式: "Mar 30 12:34:56 2026 GMT"
	str := C.GoStringN(ptr, C.int(length))

	for _, layout := range []string{
		"Jan _2 15:04:05 2006 GMT",
		"Jan _2 15:04:05 2006 MST",
		time.RFC3339,
	} {
		if parsed, err := time.Parse(layout, str); err == nil {
			return parsed, nil
		}
	}

	return time.Time{}, fmt.Errorf("failed to parse ASN1_TIME string: %s", str)
}
