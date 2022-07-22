package service

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/davecgh/go-spew/spew"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/heropan/node/nodecfg"
	"github.com/heropan/node/signal"

	"github.com/jessevdk/go-flags"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
)

type Service struct {
	Cfg    *Config
	Done   chan bool
	Node   *Node
	Client *rpcclient.Client
}

// hexToBytes converts the passed hex string into bytes and will panic if there
// is an error.  This is only provided for the hard-coded constants so errors in
// the source code can be detected. It will only (and must only) be called with
// hard-coded values.
func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in source file: " + s)
	}
	return b
}

func showOutput(v interface{}) {
	dataBytes, err := json.Marshal(v)
	if err != nil {
		fmt.Println(err)
		return
	}

	buf := new(bytes.Buffer)
	json.Indent(buf, dataBytes, "", "    ")
	fmt.Println(string(buf.Bytes()))
}

func Main(interceptor signal.Interceptor) {
	cfg, err := LoadConfig(interceptor)
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			// Print error if not due to help request.
			err = fmt.Errorf("failed to load config: %w", err)
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Help was requested, exit normally.
		os.Exit(0)
	}

	done := make(chan bool, 1)

	host, err := makeRandomNode(*cfg, done)
	if err != nil {
		fmt.Printf("make node err: %v\n", err)
		return
	}

	srv := &Service{
		Cfg:  cfg,
		Done: done,
		Node: host,
	}

	// print the node's PeerInfo in multiaddr format
	peerInfo := peer.AddrInfo{
		ID:    host.ID(),
		Addrs: host.Addrs(),
	}
	addrs, err := peer.AddrInfoToP2pAddrs(&peerInfo)
	if err != nil {
		fmt.Printf("format addr info err: %v\n", err)
		return
	}
	srvrLog.Infof("walletname: %v", srv.Cfg.walletName)
	srvrLog.Infof("network: %v", NormalizeNetwork(cfg.ActiveNetParams.Name))
	srvrLog.Infof("libp2p node address: %s", addrs[0])

	switch cfg.Bitcoin.Node {
	case "bitcoind":
		var bitcoindMode *nodecfg.Bitcoind
		bitcoindMode = cfg.BitcoindMode

		var bitcoindHost string
		if strings.Contains(bitcoindMode.RPCHost, ":") {
			bitcoindHost = bitcoindMode.RPCHost
		} else {
			// The RPC ports specified in chainparams.go assume
			// btcd, which picks a different port so that btcwallet
			// can use the same RPC port as bitcoind. We convert
			// this back to the btcwallet/bitcoind port.
			rpcPort, err := strconv.Atoi(cfg.ActiveNetParams.RPCPort)
			if err != nil {
				fmt.Printf("atoi err")
				return
			}
			rpcPort -= 2
			bitcoindHost = fmt.Sprintf("%v:%d",
				bitcoindMode.RPCHost, rpcPort)
			if cfg.Bitcoin.Active && (cfg.Bitcoin.RegTest || cfg.Bitcoin.SigNet) {

				conn, err := net.Dial("tcp", bitcoindHost)
				if err != nil || conn == nil {
					switch {
					case cfg.Bitcoin.Active && cfg.Bitcoin.RegTest:
						rpcPort = 18443
					case cfg.Bitcoin.Active && cfg.Bitcoin.SigNet:
						rpcPort = 38332
					}
					bitcoindHost = fmt.Sprintf("%v:%d",
						bitcoindMode.RPCHost,
						rpcPort)
				} else {
					conn.Close()
				}
			}
		}

		if srv.Cfg.walletName != "" {
			bitcoindHost = bitcoindHost + "/wallet/" + srv.Cfg.walletName
		}

		connCfg := &rpcclient.ConnConfig{
			Host:                 bitcoindHost,
			User:                 bitcoindMode.RPCUser,
			Pass:                 bitcoindMode.RPCPass,
			DisableAutoReconnect: false,
			DisableTLS:           true,
			HTTPPostMode:         true,
		}
		client, err := rpcclient.New(connCfg, nil)
		if err != nil {
			log.Fatal(err)
		}

		srv.Client = client

	case "btcd":
	default:
		fmt.Printf("unknown node type: %s", cfg.Bitcoin.Node)
		return
	}

	run(srv)

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

func run(srv *Service) {
	for _, p := range srv.Cfg.Peers {
		srv.Node.Peerstore().AddAddrs(p.ID, p.Addrs, peerstore.PermanentAddrTTL)
	}

	rpctest(srv.Client)
	go pingruntine(srv)
}

func rpctest(client *rpcclient.Client) {

	r1, err := client.GetAddressInfo("2MsijEHJpaHmrVkh2TuRNn5kuiVEpMRfHpM")
	if err != nil {
		fmt.Printf("rpc getaddrinfo %s err: %s", "2MsijEHJpaHmrVkh2TuRNn5kuiVEpMRfHpM", err.Error())
		return
	}
	showOutput(r1)

	// Get the list of unspent transaction outputs (utxos) that the
	// connected wallet has at least one private key for.
	unspent, err := client.ListUnspent()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Num unspent outputs (utxos): %d", len(unspent))
	if len(unspent) > 0 {
		log.Printf("First utxo:\n%v", spew.Sdump(unspent[0]))
	}

	rsp, err := client.DumpWallet("/Users/hero/wallet-a.dump.txt")
	if err != nil {
		srvrLog.Errorf("dump wallet err: %v", err)
		return
	}
	showOutput(rsp)

	//var addresses []btcutil.Address
	//addr1, err := btcutil.NewAddressPubKey(hexToBytes("0301263387b72889bdf6f0287ebf114f9099509b0cd3a72cabae3ab4d50b42c275"),
	//	cfg.ActiveNetParams.Params)
	//if err != nil {
	//	fmt.Printf("NewAddressPubKeyHash err : %s", err.Error())
	//	return
	//}
	//addresses = append(addresses, addr1)
	//addr2, err := btcutil.NewAddressPubKey(hexToBytes("02ba135d6eb72ca28b366c5806dd4a17820742c92ceb75de503d7c7f91a9cbdc8d"),
	//	cfg.ActiveNetParams.Params)
	//if err != nil {
	//	fmt.Printf("NewAddressPubKeyHash err : %s", err.Error())
	//	return
	//}
	//addresses = append(addresses, addr2)
	//addr3, err := btcutil.NewAddressPubKey(hexToBytes("0227f08c965311c8bc47c8a72c8df208038bd049d39e6eadc48dc23d136728f308"),
	//	cfg.ActiveNetParams.Params)
	//if err != nil {
	//	fmt.Printf("NewAddressPubKeyHash err : %s", err.Error())
	//	return
	//}
	//addresses = append(addresses, addr3)

	//resp, err := client.CreateMultisig(2, addresses)
	//if err != nil {
	//	fmt.Printf("rpc version err: %s", err.Error())
	//	return
	//}
	//showOutput(resp)

}

func pingruntine(srv *Service) {
	for {
		for _, p := range srv.Cfg.Peers {
			srv.Node.Ping(p.ID)
		}

		for i := 0; i < 2; i++ {
			<-srv.Done
		}
		time.Sleep(5000 * time.Millisecond)
	}
}
