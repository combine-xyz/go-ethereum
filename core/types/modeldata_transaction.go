package types

import (
	"encoding/hex"
	"errors"

	"github.com/ethereum/go-ethereum/rlp"
)

type ModelTransactionType uint8

var (
	ErrInvalidModelDataLen = errors.New("invalid model transaction length")

	ModelCreateDataPrefix   = "6d6f64656c5f7472616e73616374696f6e" //hex(sha256("model_create")[:17])
	ModelCallDataPrefix     = "6d6f64656c5f7472616e73616374696f6e" //hex(sha256("model_call")[:17])
	ModelDataPrefixBytesLen = 17

	//model transaction type
	TypeModelCreateTransaction ModelTransactionType = 1
	TypeModelCallTransaction   ModelTransactionType = 2
)

type ModelCreateTransaction struct {
	//basic infos
	ModelID uint64 `json:"blockNumLimit" gencodec:"required"`
	//model info, neccessary for create model tx
	CID         string `json:"cid"`
	Description string `json:"discription"`
	//payload data
	Payload []byte `json:"input" gencodec:"required"`
}

func IsModelTransaction(data []byte) bool {
	if len(data) >= ModelDataPrefixBytesLen {
		return IsModelCreateTransaction(data) || IsModelCallTransaction(data)
	}
	return false
}

func IsModelCreateTransaction(data []byte) bool {
	prefix := hex.EncodeToString(data[:ModelDataPrefixBytesLen])
	return prefix == ModelCreateDataPrefix
}

func DecodeModelCreateData(encodedData []byte) (modelCreateData *ModelCreateTransaction, err error) {
	modelCreateData = new(ModelCreateTransaction)
	if len(encodedData) <= ModelDataPrefixBytesLen {
		return modelCreateData, ErrInvalidModelDataLen
	}
	encodedData = encodedData[ModelDataPrefixBytesLen:]
	if err = rlp.DecodeBytes(encodedData, modelCreateData); err != nil {
		return modelCreateData, err
	}

	return
}

type ModelCallTransaction struct {
	//basic infos
	ModelID uint64 `json:"blockNumLimit" gencodec:"required"`
	//call params, neccessary for call model tx
	Params []byte `json:"params"`
	//payload data
	Payload []byte `json:"input" gencodec:"required"`
}

func DecodeModelCallData(encodedData []byte) (modelCallData *ModelCallTransaction, err error) {
	modelCallData = new(ModelCallTransaction)
	if len(encodedData) <= ModelDataPrefixBytesLen {
		return modelCallData, ErrInvalidModelDataLen
	}
	encodedData = encodedData[ModelDataPrefixBytesLen:]
	if err = rlp.DecodeBytes(encodedData, modelCallData); err != nil {
		return modelCallData, err
	}

	return
}

func IsModelCallTransaction(data []byte) bool {
	prefix := hex.EncodeToString(data[:ModelDataPrefixBytesLen])
	return prefix == ModelCallDataPrefix
}

// func (metadata *MetaData) ParseMetaData(nonce uint64, gasPrice *big.Int, gas uint64, to *common.Address, value *big.Int, payload []byte, from common.Address, chainID *big.Int) (common.Address, error) {
// 	var data interface{} = []interface{}{
// 		nonce,
// 		gasPrice,
// 		gas,
// 		to,
// 		value,
// 		payload,
// 		from,
// 		metadata.FeePercent,
// 		metadata.BlockNumLimit,
// 		chainID,
// 	}
// 	raw, _ := rlp.EncodeToBytes(data)
// 	log.Debug("meta rlpencode" + hexutil.Encode(raw[:]))
// 	hash := RlpHash(data)
// 	log.Debug("meta rlpHash", hexutil.Encode(hash[:]))

// 	var big8 = big.NewInt(8)
// 	chainMul := new(big.Int).Mul(chainID, big.NewInt(2))
// 	V := new(big.Int).Sub(metadata.V, chainMul)
// 	V.Sub(V, big8)
// 	addr, err := RecoverPlain(hash, metadata.R, metadata.S, V, true)
// 	if err != nil {
// 		return common.HexToAddress(""), ErrInvalidMetaSig
// 	}
// 	return addr, nil
// }
