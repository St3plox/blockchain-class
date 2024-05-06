package main

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
)

type Tx struct {
	FromID string `json:"from"`  // Ethereum: Account sending the transaction. Will be checked against signature.
	ToID   string `json:"to"`    // Ethereum: Account receiving the benefit of the transaction.
	Value  uint64 `json:"value"` // Ethereum: Monetary value received from this transaction.
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {

	tx := Tx{
		FromID: "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToID:   "Sosun",
		Value:  1000,
	}

	privKey, err := crypto.LoadECDSA("zblock/accounts/kennedy.ecdsa")
	if err != nil {
		return fmt.Errorf("Unable to load privKey %w", err)
	}

	data, err := json.Marshal(tx)
	if err != nil {
		return err
	}

	stamp := []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))

	v := crypto.Keccak256(stamp, data)

	sig, err := crypto.Sign(v, privKey)
	if err != nil {
		return err
	}
	fmt.Println("SIG: " + hexutil.Encode(sig))

	//===============================================================
	//OVER THE WIRE

	pubKey, err := crypto.SigToPub(v, sig)
	if err != nil {
		return err
	}

	fmt.Println("PUB: " + crypto.PubkeyToAddress(*pubKey).String())

	tx1 := Tx{
		FromID: "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToID:   "Bibas",
		Value:  250,
	}

	privKey1, err := crypto.LoadECDSA("zblock/accounts/kennedy.ecdsa")
	if err != nil {
		return fmt.Errorf("Unable to load privKey %w", err)
	}

	data1, err := json.Marshal(tx1)
	if err != nil {
		return err
	}

	stamp1 := []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data1)))
	v1 := crypto.Keccak256(stamp1, data1)

	sig1, err := crypto.Sign(v1, privKey1)
	if err != nil {
		return err
	}
	fmt.Println("SIG: " + hexutil.Encode(sig1))


	//===============================================================
	//OVER THE WIRE

	pubKey1, err := crypto.SigToPub(v, sig)
	if err != nil {
		return err
	}

	fmt.Println("PUB: " + crypto.PubkeyToAddress(*pubKey1).String())


	return nil

}
