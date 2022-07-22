package nodecfg

// Chain holds the configuration options for the daemon's chain settings.
type Chain struct {
	Active   bool   `long:"active" description:"If the chain should be active or not."`
	ChainDir string `long:"chaindir" description:"The directory to store the chain's data within."`

	Node string `long:"node" description:"The blockchain interface to use." choice:"btcd" choice:"bitcoind"`

	MainNet         bool     `long:"mainnet" description:"Use the main network"`
	TestNet3        bool     `long:"testnet" description:"Use the test network"`
	SimNet          bool     `long:"simnet" description:"Use the simulation test network"`
	RegTest         bool     `long:"regtest" description:"Use the regression test network"`
	SigNet          bool     `long:"signet" description:"Use the signet test network"`
	SigNetChallenge string   `long:"signetchallenge" description:"Connect to a custom signet network defined by this challenge instead of using the global default signet test network -- Can be specified multiple times"`
	SigNetSeedNode  []string `long:"signetseednode" description:"Specify a seed node for the signet network instead of using the global default signet network seed nodes"`
}
