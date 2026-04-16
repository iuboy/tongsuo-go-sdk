// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"unsafe"
)

type NID int

const (
	NidUndef                          NID = 0
	NidRsadsi                         NID = 1
	NidPkcs                           NID = 2
	NidMd2                            NID = 3
	NidMd5                            NID = 4
	NidRc4                            NID = 5
	NidRsaEncryption                  NID = 6
	NidMd2WithRSAEncryption           NID = 7
	NidMd5WithRSAEncryption           NID = 8
	NidPbeWithMD2AndDESCBC            NID = 9
	NidPbeWithMD5AndDESCBC            NID = 10
	NidX500                           NID = 11
	NidX509                           NID = 12
	NidCommonName                     NID = 13
	NidCountryName                    NID = 14
	NidLocalityName                   NID = 15
	NidStateOrProvinceName            NID = 16
	NidOrganizationName               NID = 17
	NidOrganizationalUnitName         NID = 18
	NidRsa                            NID = 19
	NidPkcs7                          NID = 20
	NidPkcs7Data                      NID = 21
	NidPkcs7Signed                    NID = 22
	NidPkcs7Enveloped                 NID = 23
	NidPkcs7SignedAndEnveloped        NID = 24
	NidPkcs7Digest                    NID = 25
	NidPkcs7Encrypted                 NID = 26
	NidPkcs3                          NID = 27
	NidDhKeyAgreement                 NID = 28
	NidDesEcb                         NID = 29
	NidDesCfb64                       NID = 30
	NidDesCbc                         NID = 31
	NidDesEde                         NID = 32
	NidDesEde3                        NID = 33
	NidIdeaCbc                        NID = 34
	NidIdeaCfb64                      NID = 35
	NidIdeaEcb                        NID = 36
	NidRc2Cbc                         NID = 37
	NidRc2Ecb                         NID = 38
	NidRc2Cfb64                       NID = 39
	NidRc2Ofb64                       NID = 40
	NidSha                            NID = 41
	NidShaWithRSAEncryption           NID = 42
	NidDesEdeCbc                      NID = 43
	NidDesEde3Cbc                     NID = 44
	NidDesOfb64                       NID = 45
	NidIdeaOfb64                      NID = 46
	NidPkcs9                          NID = 47
	NidPkcs9EmailAddress              NID = 48
	NidPkcs9UnstructuredName          NID = 49
	NidPkcs9ContentType               NID = 50
	NidPkcs9MessageDigest             NID = 51
	NidPkcs9SigningTime               NID = 52
	NidPkcs9Countersignature          NID = 53
	NidPkcs9ChallengePassword         NID = 54
	NidPkcs9UnstructuredAddress       NID = 55
	NidPkcs9ExtCertAttributes         NID = 56
	NidNetscape                       NID = 57
	NidNetscapeCertExtension          NID = 58
	NidNetscapeDataType               NID = 59
	NidDesEdeCfb64                    NID = 60
	NidDesEde3Cfb64                   NID = 61
	NidDesEdeOfb64                    NID = 62
	NidDesEde3Ofb64                   NID = 63
	NidSha1                           NID = 64
	NidSha1WithRSAEncryption          NID = 65
	NidDsaWithSHA                     NID = 66
	NidDsa2                           NID = 67
	NidPbeWithSHA1AndRC2CBC           NID = 68
	NidIDPbkdf2                       NID = 69
	NidDsaWithSHA12                   NID = 70
	NidNetscapeCertType               NID = 71
	NidNetscapeBaseURL                NID = 72
	NidNetscapeRevocationURL          NID = 73
	NidNetscapeCaRevocationURL        NID = 74
	NidNetscapeRenewalURL             NID = 75
	NidNetscapeCaPolicyURL            NID = 76
	NidNetscapeSslServerName          NID = 77
	NidNetscapeComment                NID = 78
	NidNetscapeCertSequence           NID = 79
	NidDesxCbc                        NID = 80
	NidIDCe                           NID = 81
	NidSubjectKeyIdentifier           NID = 82
	NidKeyUsage                       NID = 83
	NidPrivateKeyUsagePeriod          NID = 84
	NidSubjectAltName                 NID = 85
	NidIssuerAltName                  NID = 86
	NidBasicConstraints               NID = 87
	NidCrlNumber                      NID = 88
	NidCertificatePolicies            NID = 89
	NidAuthorityKeyIdentifier         NID = 90
	NidBfCbc                          NID = 91
	NidBfEcb                          NID = 92
	NidBfCfb64                        NID = 93
	NidBfOfb64                        NID = 94
	NidMdc2                           NID = 95
	NidMdc2WithRSA                    NID = 96
	NidRc440                          NID = 97
	NidRc240Cbc                       NID = 98
	NidGivenName                      NID = 99
	NidSurname                        NID = 100
	NidInitials                       NID = 101
	NidUniqueIdentifier               NID = 102
	NidCrlDistributionPoints          NID = 103
	NidMd5WithRSA                     NID = 104
	NidSerialNumber                   NID = 105
	NidTitle                          NID = 106
	NidDescription                    NID = 107
	NidCast5Cbc                       NID = 108
	NidCast5Ecb                       NID = 109
	NidCast5Cfb64                     NID = 110
	NidCast5Ofb64                     NID = 111
	NidPbeWithMD5AndCast5CBC          NID = 112
	NidDsaWithSHA1                    NID = 113
	NidMd5Sha1                        NID = 114
	NidSha1WithRSA                    NID = 115
	NidDsa                            NID = 116
	NidRipemd160                      NID = 117
	NidRipemd160WithRSA               NID = 119
	NidRc5Cbc                         NID = 120
	NidRc5Ecb                         NID = 121
	NidRc5Cfb64                       NID = 122
	NidRc5Ofb64                       NID = 123
	NidRleCompression                 NID = 124
	NidZlibCompression                NID = 125
	NidExtKeyUsage                    NID = 126
	NidIDPkix                         NID = 127
	NidIDKp                           NID = 128
	NidServerAuth                     NID = 129
	NidClientAuth                     NID = 130
	NidCodeSign                       NID = 131
	NidEmailProtect                   NID = 132
	NidTimeStamp                      NID = 133
	NidMsCodeInd                      NID = 134
	NidMsCodeCom                      NID = 135
	NidMsCtlSign                      NID = 136
	NidMsSgc                          NID = 137
	NidMsEfs                          NID = 138
	NidNsSgc                          NID = 139
	NidDeltaCrl                       NID = 140
	NidCrlReason                      NID = 141
	NidInvalidityDate                 NID = 142
	NidSxnet                          NID = 143
	NidPbeWithSHA1And128BitRC4        NID = 144
	NidPbeWithSHA1And40BitRC4         NID = 145
	NidPbeWithSHA1And3KeyTripleDESCBC NID = 146
	NidPbeWithSHA1And2KeyTripleDESCBC NID = 147
	NidPbeWithSHA1And128BitRC2CBC     NID = 148
	NidPbeWithSHA1And40BitRC2CBC      NID = 149
	NidKeyBag                         NID = 150
	NidPkcs8ShroudedKeyBag            NID = 151
	NidCertBag                        NID = 152
	NidCrlBag                         NID = 153
	NidSecretBag                      NID = 154
	NidSafeContentsBag                NID = 155
	NidFriendlyName                   NID = 156
	NidLocalKeyID                     NID = 157
	NidX509Certificate                NID = 158
	NidSdsiCertificate                NID = 159
	NidX509Crl                        NID = 160
	NidPbes2                          NID = 161
	NidPbmac1                         NID = 162
	NidHmacWithSHA1                   NID = 163
	NidIDQtCps                        NID = 164
	NidIDQtUnotice                    NID = 165
	NidRc264Cbc                       NID = 166
	NidSMIMECapabilities              NID = 167
	NidPbeWithMD2AndRC2CBC            NID = 168
	NidPbeWithMD5AndRC2CBC            NID = 169
	NidPbeWithSHA1AndDESCBC           NID = 170
	NidMsExtReq                       NID = 171
	NidExtReq                         NID = 172
	NidName                           NID = 173
	NidDnQualifier                    NID = 174
	NidIDPe                           NID = 175
	NidIDAd                           NID = 176
	NidInfoAccess                     NID = 177
	NidAdOCSP                         NID = 178
	NidAdCaIssuers                    NID = 179
	NidOCSPSign                       NID = 180
	NidX962IdEcPublicKey              NID = 408
	NidHmac                           NID = 855
	NidCmac                           NID = 894
	NidDhpublicnumber                 NID = 920
	NidTLS1Prf                        NID = 1021
	NidHkdf                           NID = 1036
	NidX25519                         NID = 1034
	NidX448                           NID = 1035
	NidEd25519                        NID = 1087
	NidEd448                          NID = 1088
	NidSM2                            NID = 1172

	// GM/T 国密算法 NID 常量
	// 注意：这些值对应 Tongsuo 8.5+ (基于 OpenSSL 3.x) 的 NID 分配。
	// 不同版本的 Tongsuo/OpenSSL 可能使用不同的 NID 值。
	// 使用 LookupNID() 可在运行时通过 OID 字符串查找 NID。

	// SM3 密码杂凑算法 (GM/T 0003-2012)
	// OID: 1.2.156.10197.1.401
	NidSM3 NID = 1145

	// SM4 分组密码 (GM/T 0004-2012)
	// OID: 1.2.156.10197.1.104
	NidSM4 NID = 913

	// SM4-ECB 模式
	NidSM4ECB NID = 914

	// SM4-CBC 模式
	NidSM4CBC NID = 915

	// SM4-CTR 模式
	NidSM4CTR NID = 916

	// SM2-SM3 签名算法 (GM/T 0009-2012)
	// OID: 1.2.156.10197.1.501
	NidSM2WithSM3 NID = 1173
)

// LookupNID resolves an OID string (e.g. "1.2.156.10197.1.301") to its NID
// using the Tongsuo library's OID table. Returns an error if the OID is unknown.
func LookupNID(oid string) (NID, error) {
	if oid == "" {
		return 0, fmt.Errorf("empty OID string")
	}
	cOID := C.CString(oid)
	defer C.free(unsafe.Pointer(cOID))
	nid := C.OBJ_txt2nid(cOID)
	if nid == 0 {
		return 0, fmt.Errorf("unknown OID: %q", oid)
	}
	return NID(nid), nil
}
