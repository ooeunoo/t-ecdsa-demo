// iodkg/dkg_io.go

package iodkg

import (
	"encoding/json"
	"io/ioutil"
	"log"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/protocol"
	dkls "github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type DkgData struct {
	Alice   protocol.Message `json:"alice"`
	Bob     protocol.Message `json:"bob"`
	Address string           `json:"address"`
}

func SaveDkgData(aliceDkg *dkg.Alice, bobDkg *dkg.Bob, address common.Address, filename string) error {
	aliceMsg, err := dkls.EncodeAliceDkgOutput(aliceDkg.Output(), protocol.Version1)
	if err != nil {
		return err
	}

	bobMsg, err := dkls.EncodeBobDkgOutput(bobDkg.Output(), protocol.Version1)
	if err != nil {
		return err
	}

	data := DkgData{
		Alice:   *aliceMsg,
		Bob:     *bobMsg,
		Address: address.Hex(),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, jsonData, 0644)
}

func LoadDkgData(filename string, curve *curves.Curve) (*dkg.AliceOutput, *dkg.BobOutput, common.Address, error) {
	jsonData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, common.Address{}, err
	}

	var data DkgData
	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		return nil, nil, common.Address{}, err
	}

	aliceOutput, err := dkls.DecodeAliceDkgResult(&data.Alice)
	if err != nil {
		return nil, nil, common.Address{}, err
	}

	bobOutput, err := dkls.DecodeBobDkgResult(&data.Bob)
	if err != nil {
		return nil, nil, common.Address{}, err
	}

	// savedAddress := common.HexToAddress(data.Address)
	pkA := curve.ScalarBaseMult(aliceOutput.SecretKeyShare)
	computedPublicKeyA := pkA.Mul(bobOutput.SecretKeyShare)
	publicKeyBytes := computedPublicKeyA.ToAffineUncompressed()
	publicKeyUnmarshal, err := crypto.UnmarshalPubkey(publicKeyBytes)
	if err != nil {
		log.Fatalf("Failed to unmarshal public key: %v", err)
	}
	address := crypto.PubkeyToAddress(*publicKeyUnmarshal)

	return aliceOutput, bobOutput, address, nil
}
