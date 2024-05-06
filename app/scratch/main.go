package main

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
)

type Tx struct {
	FromID  string `json:"from"`     // Ethereum: Account sending the transaction. Will be checked against signature.
	ToID    string `json:"to"`       // Ethereum: Account receiving the benefit of the transaction.
	Value   uint64    `json:"value"`    // Ethereum: Monetary value received from this transaction.
}

func main()  {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error{

	tx := Tx{
		FromID: "Soser",
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
	
	v := crypto.Keccak256(data)

	sig, err := crypto.Sign(v, privKey)
	if err != nil {
		return err
	}
	fmt.Println("SIG: " +  hexutil.Encode(sig))

	//===============================================================
	//OVER THE WIRE

	pubKey, err := crypto.SigToPub(v, sig)
	if err != nil {
		return err
	}

	fmt.Println("PUB: " + crypto.PubkeyToAddress(*pubKey).String())

	return nil
}
