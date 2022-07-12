package chainreg

import (
	bitcoinCfg "github.com/btcsuite/btcd/chaincfg"
	bitcoinWire "github.com/btcsuite/btcd/wire"
)

const (
	// CoinTypeBitcoin specifies the BIP44 coin type for Bitcoin key
	// derivation.
	CoinTypeBitcoin uint32 = 0

	// CoinTypeTestnet specifies the BIP44 coin type for all testnet key
	// derivation.
	CoinTypeTestnet = 1
)

// BitcoinNetParams couples the p2p parameters of a network with the
// corresponding RPC port of a daemon running on the particular network.
type BitcoinNetParams struct {
	*bitcoinCfg.Params
	RPCPort  string
	CoinType uint32
}

// BitcoinTestNetParams contains parameters specific to the 3rd version of the
// test network.
var BitcoinTestNetParams = BitcoinNetParams{
	Params:   &bitcoinCfg.TestNet3Params,
	RPCPort:  "18334",
	CoinType: CoinTypeTestnet,
}

// BitcoinMainNetParams contains parameters specific to the current Bitcoin
// mainnet.
var BitcoinMainNetParams = BitcoinNetParams{
	Params:   &bitcoinCfg.MainNetParams,
	RPCPort:  "8334",
	CoinType: CoinTypeBitcoin,
}

// BitcoinSimNetParams contains parameters specific to the simulation test
// network.
var BitcoinSimNetParams = BitcoinNetParams{
	Params:   &bitcoinCfg.SimNetParams,
	RPCPort:  "18556",
	CoinType: CoinTypeTestnet,
}

// BitcoinSigNetParams contains parameters specific to the signet test network.
var BitcoinSigNetParams = BitcoinNetParams{
	Params:   &bitcoinCfg.SigNetParams,
	RPCPort:  "38332",
	CoinType: CoinTypeTestnet,
}

// BitcoinRegTestNetParams contains parameters specific to a local bitcoin
// regtest network.
var BitcoinRegTestNetParams = BitcoinNetParams{
	Params:   &bitcoinCfg.RegressionNetParams,
	RPCPort:  "18334",
	CoinType: CoinTypeTestnet,
}

// IsTestnet tests if the givern params correspond to a testnet
// parameter configuration.
func IsTestnet(params *BitcoinNetParams) bool {
	switch params.Params.Net {
	case bitcoinWire.TestNet3:
		return true
	default:
		return false
	}
}
