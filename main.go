package main

import (
	"fmt"
	"github.com/libp2p/go-libp2p-core/peer"
	"log"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peerstore"
	ma "github.com/multiformats/go-multiaddr"
)

func main() {
	port := 10000

	done := make(chan bool, 1)

	// Make 2 hosts
	host := makeRandomNode(port, done)

	log.Printf("host ID %s\n", host.ID())

	run(host, done)
}

// helper method - create a lib-p2p host to listen on a port
func makeRandomNode(port int, done chan bool) *Node {
	// Ignoring most errors for brevity
	// See echo example for more details and better implementation
	priv, _, _ := crypto.GenerateKeyPair(crypto.Secp256k1, 256)
	listen, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port))
	host, _ := libp2p.New(
		libp2p.ListenAddrs(listen),
		libp2p.Identity(priv),
	)

	return NewNode(host, done)
}

func run(host *Node, done <-chan bool) {
	// connect peers
	addressList := []string{}
	var addrInfo []peer.AddrInfo
	// Turn the destination into a multiaddr.
	for _, addr := range addressList {
		ainfo, err := peer.AddrInfoFromString(addr)
		if err != nil {
			log.Println(err)
			return
		}
		addrInfo = append(addrInfo, *ainfo)
	}

	for _, addr := range addrInfo {
		host.Peerstore().AddAddrs(addr.ID, addr.Addrs, peerstore.PermanentAddrTTL)
		host.Ping(addr.ID)
	}

	// block until all responses have been processed
	for i := 0; i < 8; i++ {
		<-done
	}
}
