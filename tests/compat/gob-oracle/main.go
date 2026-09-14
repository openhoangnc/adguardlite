// Command gob-oracle encodes and decodes AdGuard Home's statistics unit with
// Go's own encoding/gob, so the Rust implementation can be checked against the
// implementation it has to interoperate with.
//
//	gob-oracle encode <out.gob>   write a populated unit
//	gob-oracle decode <in.gob>    decode a unit and print it as JSON
package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"
)

// countPair mirrors internal/stats.countPair.
type countPair struct {
	Name  string
	Count uint64
}

// unitDB mirrors internal/stats.unitDB.  The field names and types are part of
// the gob encoding and must not drift.
type unitDB struct {
	NResult            []uint64
	Domains            []countPair
	BlockedDomains     []countPair
	Clients            []countPair
	UpstreamsResponses []countPair
	UpstreamsTimeSum   []countPair
	NTotal             uint64
	TimeAvg            uint32
}

// sample returns a unit with every field populated, including values that
// exercise the encoding's edge cases.
func sample() unitDB {
	return unitDB{
		NResult: []uint64{0, 1200, 340, 5, 0, 7},
		Domains: []countPair{
			{Name: "example.com", Count: 512},
			{Name: "en.wikipedia.org", Count: 128},
			{Name: "xn--80ak6aa92e.com", Count: 1},
		},
		BlockedDomains: []countPair{
			{Name: "doubleclick.net", Count: 341},
			{Name: "ads.example.com", Count: 9},
		},
		Clients: []countPair{
			{Name: "192.168.1.5", Count: 900},
			{Name: "2001:db8::1", Count: 3},
		},
		UpstreamsResponses: []countPair{
			{Name: "https://dns10.quad9.net:443/dns-query", Count: 871},
		},
		UpstreamsTimeSum: []countPair{
			{Name: "https://dns10.quad9.net:443/dns-query", Count: 143_119_999},
		},
		NTotal:  1552,
		TimeAvg: 397,
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: gob-oracle encode|decode <file>")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "encode":
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(sample()); err != nil {
			panic(err)
		}
		if err := os.WriteFile(os.Args[2], buf.Bytes(), 0o644); err != nil {
			panic(err)
		}
		fmt.Printf("wrote %d bytes\n", buf.Len())

	case "decode":
		b, err := os.ReadFile(os.Args[2])
		if err != nil {
			panic(err)
		}
		var u unitDB
		if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&u); err != nil {
			fmt.Fprintf(os.Stderr, "DECODE FAILED: %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(u, "", " ")
		fmt.Println(string(out))

	case "expected":
		out, _ := json.MarshalIndent(sample(), "", " ")
		fmt.Println(string(out))

	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}
