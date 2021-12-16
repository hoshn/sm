package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/ZZMarquis/gm/sm4"
	"github.com/ZZMarquis/gm/util"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/x509"
	"go/types"
)

/* 加解密类型 */
var (
	smType string
	str    string
	smRes	string
	smErr  types.Nil
)

/* SM2 加密参数*/
var (
	pubKey    string
	randomKey string
	randomIV  string
)

/* SM2 解密参数*/
var (
	privKey string
)

/* SM4 加密参数*/
var (
	sm4PrivKey string
	paddingType string
	sm4IV string
)

func init() {
	flag.StringVar(&smType, "smType", "", "")
	flag.StringVar(&str, "str", "", "")
	flag.StringVar(&privKey, "privKey", "", "")
	flag.StringVar(&pubKey, "pubKey", "", "")
	flag.StringVar(&randomKey, "randomKey", "", "")
	flag.StringVar(&randomIV, "randomIV", "", "")
	flag.StringVar(&sm4PrivKey, "sm4PrivKey", "", "")
	flag.StringVar(&paddingType, "paddingType", "CBC", "")
	flag.StringVar(&sm4IV, "sm4IV", "", "")
}

func main() {
	flag.Parse()
	switch smType {
	case "sm2Encrypt":
		sm2Encrypt()
	case "sm2Decrypt":
		sm2Decrypt()
	case "sm3Hash":
		sm3Hash()
	case "sm4Encrypt":
		sm4Encrypt()
	case "sm4Decrypt":
		sm4Decrypt()
	default:

	}

	fmt.Println(smRes)
}

/* sm2非对称加密
 * DEMO：
	go run main.go -smType sm2Encrypt -str abc -pubKey 04fc8e60b7974965284ce76e319ea0295b5f785f433069b68343d0f8453a63ba8e31734373bb59dc31f7806fc69d060eb91ad32810bd280901372f327510521937
*/
func sm2Encrypt() {
	if len(str) > 0 && len(pubKey) > 0 {
		smPubKey, _ := x509.ReadPublicKeyFromHex(pubKey)
		resByte, _ := smPubKey.EncryptAsn1([]byte(str), rand.Reader)
		//fmt.Printf("加密：%x\n", resByte)
		smRes = hex.EncodeToString(resByte)
	}
}

/* sm2非对称解密
 * DEMO：
	go run main.go -smType sm2Decrypt -str 306b022063d6ced4dfc7bc2b2f80a5570293640f5b30fe4637791b3bffa502d5e730492a022073e9bf9e744056dfec56b37c05c42befbf6c2825d18e6ce1a55e78974670d7210420dac89cf4b4000612cdcc66272e0d117b33b7b95e3d47b279332aecf4ba891aa104032d0304 -privKey ddae96473a756fcb3ec3eab140ad3b1005ba54a9a2817b0940d2f37ded2c4451
*/
func sm2Decrypt() {
	if len(str) > 0 && len(privKey) > 0 { //&& len(randomKey) > 0
		smPrivKey, _ := x509.ReadPrivateKeyFromHex(privKey)
		hexStr, _ := hex.DecodeString(str)
		resByte, _ := smPrivKey.DecryptAsn1([]byte(hexStr))

		smRes = fmt.Sprintf("%s", resByte)
	}
}

/*
 * sm3 HASH
 * DEMO：
   go run main.go -smType sm3Hash -str 111
*/
func sm3Hash() {
	smRes = fmt.Sprintf("%x", sm3.Sm3Sum([]byte(str)))
}


/* sm4对称加密
 * DEMO：
go run main.go -smType sm4Encrypt -str abc -sm4PrivKey 524d69faaa0eb268 -sm4IV dcac050c27357873
go run main.go -smType sm4Encrypt -str '{"aaa":1112,"aaa":1112,"aaa":1112,"aaa":1112}' -sm4PrivKey 524d69faaa0eb268524d69faaa0eb268 -sm4IV dcac050c27357873dcac050c27357873
*/
func sm4Encrypt() {
	inputBytes := util.PKCS5Padding([]byte(str), sm4.BlockSize)
	if paddingType == "ECB" {
		resByte, smErr := sm4.ECBEncrypt([]byte(sm4PrivKey), inputBytes)
		if smErr != nil {
			smRes = ""
		}
		smRes = fmt.Sprintf("%x", resByte)
	} else {
		resByte, smErr := sm4.CBCEncrypt([]byte(sm4PrivKey), []byte(sm4IV), inputBytes)
		if smErr != nil {
			smRes = ""
		}
		smRes = fmt.Sprintf("%s", hex.EncodeToString(resByte))
	}

}


/**
* sm4对称解密：
* DEMO：
go run main.go -smType sm4Decrypt -str f96d3eabb098b072d86f101c83399076 -sm4PrivKey 524d69faaa0eb268 -sm4IV dcac050c27357873
*/
func sm4Decrypt() {
	hexStr, _ := hex.DecodeString(str)
	if paddingType == "ECB" {
		resByte, smErr := sm4.ECBDecrypt([]byte(sm4PrivKey), hexStr)
		if smErr != nil {
			smRes = ""
		}
		smRes = fmt.Sprintf("%s", util.PKCS5UnPadding(resByte))
	} else {
		resByte, smErr := sm4.CBCDecrypt([]byte(sm4PrivKey), []byte(sm4IV), hexStr)
		if smErr != nil {
			smRes = ""
		}
		smRes = fmt.Sprintf("%s", util.PKCS5UnPadding(resByte))
	}
}

