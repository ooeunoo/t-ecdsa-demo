package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	ecdsa_lib "server/tss"

	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"
)

func main() {
	// Parties 초기화
	pA := ecdsa_lib.NewParty(1, logger("pA", ""))
	pB := ecdsa_lib.NewParty(2, logger("pB", ""))
	pC := ecdsa_lib.NewParty(3, logger("pC", ""))

	// Parties 슬라이스 생성
	parties := ecdsa_lib.Parties{pA, pB, pC}

	// Parties 초기화 및 통신 설정
	parties.InitPartiesWrap(ecdsa_lib.Senders(parties))

	// 키 생성 수행 (분산 키 생성 - DKG)
	shares, _ := parties.KeygenWrap()

	// 생성된 각 Share 출력
	for i, share := range shares {
		fmt.Printf("")
		fmt.Printf("분할키 %d:\n", i+1)
		fmt.Println(hex.EncodeToString(share))
		fmt.Printf("")
	}

	// Parties에 Share 데이터 설정
	parties.SetShareDataWrap(shares)

	// 서명할 메시지
	msgToSign := []byte("bla bla")

	// 메시지 서명 수행
	sigs, _ := parties.SignWrap(digest(msgToSign))

	// // 서명 집합 생성
	// sigSet := make(map[string]struct{})
	// for _, s := range sigs {
	// 	sigSet[string(s)] = struct{}{}
	// }

	// Parties의 첫 번째 Party의 공개키 획득 (*모든 파티는 동일한 Publick Key를 가짐)
	pk, _ := parties[0].TPubKey()

	fmt.Printf("")
	fmt.Println("pk:", pk)
	fmt.Printf("")
	ethereumAddress := crypto.PubkeyToAddress(*pk).Hex()
	fmt.Printf("")
	fmt.Println("주소:", ethereumAddress)
	fmt.Printf("")

	// ECDSA 서명 데이터(r, s) 출력 및 검증
	for i, sig := range sigs {
		fmt.Printf("Signature %d:\n", i+1)
		r, s, err := parseECDSASignature(sig)
		if err != nil {
			fmt.Printf("서명 파싱 오류: %v\n", err)
			continue
		}
		fmt.Printf("r: %s\n", r.Text(16))
		fmt.Printf("s: %s\n", s.Text(16))

		// 서명 검증
		valid := verifyECDSASignature(msgToSign, r, s, pk)
		if valid {
			fmt.Println("서명 유효성 검증 성공.")
		} else {
			fmt.Println("서명 유효성 검증 실패.")
		}
	}

}

// ECDSA r, s 추출
func parseECDSASignature(sig []byte) (*big.Int, *big.Int, error) {
	var ecdsaSig struct {
		R *big.Int
		S *big.Int
	}
	_, err := asn1.Unmarshal(sig, &ecdsaSig)
	if err != nil {
		return nil, nil, err
	}
	return ecdsaSig.R, ecdsaSig.S, nil
}

// ECDSA 서명의 유효성ㄴ 검증.
func verifyECDSASignature(msg []byte, r, s *big.Int, publicKey *ecdsa.PublicKey) bool {
	// 메시지 해싱
	msgHash := digest(msg)
	// 서명 검증
	valid := ecdsa.Verify(publicKey, msgHash, r, s)
	return valid
}

// 로깅
func logger(id string, testName string) *zap.SugaredLogger {
	logConfig := zap.NewDevelopmentConfig()
	logger, _ := logConfig.Build()
	logger = logger.With(zap.String("t", testName), zap.String("id", id))
	return logger.Sugar()
}

func digest(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}
