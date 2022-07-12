package service

import (
	"errors"
	"github.com/heropan/node/signal"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
)

func Main(interceptor signal.Interceptor) {
	cfg, err := LoadConfig(interceptor)
	if err != nil {
		panic(err)
	}

	done := make(chan bool, 1)

	host, err := makeRandomNode(*cfg, done)
	if err != nil {
		panic(err)
	}

	// print the node's PeerInfo in multiaddr format
	peerInfo := peer.AddrInfo{
		ID:    host.ID(),
		Addrs: host.Addrs(),
	}
	addrs, err := peer.AddrInfoToP2pAddrs(&peerInfo)
	if err != nil {
		panic(err)
	}
	srvrLog.Infof("libp2p node address: %s", addrs[0])

	run(*cfg, host)

	<-interceptor.ShutdownChannel()
}

// helper method - create a lib-p2p host to listen on a port
func makeRandomNode(cfg Config, done chan bool) (*Node, error) {
	// Ignoring most errors for brevity
	// See echo example for more details and better implementation
	var priv crypto.PrivKey
	var err error

	if len(cfg.IdentityKey) == 0 {
		srvrLog.Errorf("no idkey configured")

		priv, _, err = crypto.GenerateKeyPair(crypto.Secp256k1, 256)
		if err != nil {
			srvrLog.Errorf("generate key pair err: %s", err.Error())
			return nil, err
		}

		prvRaw, err := crypto.MarshalPrivateKey(priv)
		if err != nil {
			srvrLog.Errorf("get priv key raw err: %s", err.Error())
			return nil, err
		}

		prvStr := crypto.ConfigEncodeKey(prvRaw)
		srvrLog.Errorf("randomly generate one: %s", prvStr)
		return nil, errors.New("configure idkey first")
	} else {
		prvRaw, err := crypto.ConfigDecodeKey(cfg.IdentityKey)
		if err != nil {
			srvrLog.Errorf("decode key err: %s", err.Error())
			return nil, err
		}

		priv, err = crypto.UnmarshalPrivateKey(prvRaw)
		if err != nil {
			srvrLog.Errorf("unmarshal priv key err: %s", err.Error())
			return nil, err
		}
	}

	host, _ := libp2p.New(
		libp2p.ListenAddrs(cfg.Listeners[0]),
		libp2p.Identity(priv),
	)

	return NewNode(host, done), nil
}

func run(cfg Config, host *Node) {
	// connect peers
	//addressList := []string{
	//	"/ip4/127.0.0.1/tcp/10000/p2p/16Uiu2HAmPfWPo3HesfTFoqTc3cQz3JsCf9RTKRN7woJNWEBuwANm",
	//}

	for _, p := range cfg.Peers {
		host.Peerstore().AddAddrs(p.ID, p.Addrs, peerstore.PermanentAddrTTL)
	}

	for _, p := range cfg.Peers {
		host.Ping(p.ID)
	}
}
