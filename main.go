package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

func main() {
	// binance test net https://testnet.bscscan.com/block/9983800
	blockJSON := `{"hash":"0xb73471b4727e4bf6168a825eef4ff7da8be273148460ad68cf551d84d1e26f83","parentHash":"0x219f467df5a8631afe3e81ee8b295f324a2c94b2b0651563c714b1c1ff4ce80f","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","miner":"0x1284214b9b9c85549ab3d2b972df0deef66ac2c9","stateRoot":"0x6b20099ec336b3fad1f67a47ef8fe08e08ca833fa743f7cdd61679d4deab281d","transactionsRoot":"0xac8a9d033270098f3a5c4c30fef0a1383199a5a5c487b8840bce91b1a69fed41","receiptsRoot":"0x4e7133b777fd8d5fa4aa1bee1cdfe853a56fce7e1961e4d13dc71fdd611542f8","number":"0x985738","gasUsed":"0x353302","gasLimit":"0x1c7f9be","extraData":"0xd883010100846765746888676f312e31352e35856c696e75780000001600553d1284214b9b9c85549ab3d2b972df0deef66ac2c935552c16704d214347f29fa77f77da6d75d7c7523679479c2402e921db00923e014cd439c606c5967a1a4ad9cc746a70ee58568466f7996dd0ace4e896c5d20b2a975c050e4220be276ace4892f4b41a980a75ecd1309ea12fa2ed87a8744fbfc9b863d5a2959d3f95eae5dc7d70144ce1b73b403b7eb6e0b71b214cb885500844365e95cd9942c7276e7fd8c89c669357d161d57b0b255c94ea96e179999919e625dd7ad2f7b88723857946a41af646c589c336c56695dd415bdf7daf92157dbd96f5d575897af9dcd0afd6966a12168c62238f72e83706a5cd9c9d6bc50ede03fc998283570e5564db617ea7c9684284b1554a01","logsBloom":"0x10000000000000000000000000000000000000000000000000200000000000000000002000000020400000000000000000000000000000000000000000002002000000008000000000000008000000012010020000000000000000001000000000010020020200000000000000000840200000000000008000000010000000000000000000000000000000000000000000000440000000000000000000000000000000800000000000000000020000000200000000000000000000000000080000000002800000000000000200100000000002000000000000000000000020000000000000001000410000804000000000000000000000080000000000000000","timestamp":"0x60d31ee4","difficulty":"0x2","totalDifficulty":"0x12f5d2a","sealFields":[],"uncles":[],"transactions":["0x39e3bea5b9fa23e74f62914d0835292644b9b6dc9b7baca3de25fd4a2b1d6cfd","0x76606e976b1facaf44b03318352eef140d29ff0119cc52162a71a235daca293c","0xbd42ff71bce5dae23716590c84d564bc6b902a3be972615a8617eced51e7478f","0xde518beaceef158d9aead03c01643bf9c798a7154f61937e7b9c4fafb23fae80","0x90927cd240db2d970ee14da3b2adc9cea1508a91c00501d68eac98487ea71119","0xb38ce2b7991f2e8ee069e7797060f82dc300a2148c3860e38de95a4ca83d625c"],"size":"0x3e92","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000"}`
	var block types.Header
	err := json.Unmarshal([]byte(blockJSON), &block)
	if err != nil {
		log.Fatal(err)
	}

	hasher := sha3.NewLegacyKeccak256()

	err = rlp.Encode(hasher, []interface{}{
		big.NewInt(97),
		block.ParentHash,
		block.UncleHash,
		block.Coinbase,
		block.Root,
		block.TxHash,
		block.ReceiptHash,
		block.Bloom,
		block.Difficulty,
		block.Number,
		block.GasLimit,
		block.GasUsed,
		block.Time,
		block.Extra[:len(block.Extra)-65],
		block.MixDigest,
		block.Nonce,
	})
	if err != nil {
		log.Fatal(err)
	}

	hash := common.Hash{}
	hasher.Sum(hash[:0])

	fmt.Println("---------------------------")
	fmt.Println("hash length =>", len(hash.Bytes()))
	fmt.Println("hash bytes =>", hash.Bytes())
	fmt.Println("hash =>", hash)
	fmt.Println("---------------------------")

	signature := block.Extra[len(block.Extra)-65:]
	pubkey, err := secp256k1.RecoverPubkey(hash.Bytes(), signature)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("---------------------------")
	fmt.Println("pubkey length", len(pubkey))
	fmt.Println("pubkey bytes", pubkey)
	fmt.Println("pubkey", hexutil.Encode(pubkey))
	fmt.Println("---------------------------")

	// finael validator address
	// target address: 0x1284214b9b9c85549ab3d2b972df0deef66ac2c9
	fmt.Println(hexutil.Encode(crypto.Keccak256(pubkey[1:])[12:]))
}
