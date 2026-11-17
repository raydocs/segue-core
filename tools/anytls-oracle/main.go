// Command anytls-oracle writes the vectors segue-core's AnyTLS tests compare
// against: the default padding scheme's digest and per-counter record sizes as
// sing-anytls computes them, the hello a client sends, and the frames for one
// stream. Run it with the sing-anytls module available:
//
//	cd tools/anytls-oracle && go mod tidy && go run . out.json
//
// The output is synthetic test data: the password is a fixed placeholder, so
// nothing here is a credential or a live endpoint.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/anytls/sing-anytls/padding"
)

type vector struct {
	Name              string   `json:"name"`
	PaddingSchemeMD5  string   `json:"paddingSchemeMd5"`
	PasswordSHA256    string   `json:"passwordSha256"`
	Stop              uint32   `json:"stop"`
	HelloPadding      int      `json:"helloPadding"`
	RecordSizes       [][]int  `json:"recordSizes"`
	SettingsPayload   string   `json:"settingsPayload"`
	FirstPushFrameHex string   `json:"firstPushFrameHex"`
	Notes             []string `json:"notes"`
}

const syntheticPassword = "synthetic-example-anytls-password"

func sizes(factory *padding.PaddingFactory, packet uint32) []int {
	// The reference draws each range from crypto/rand, so a range entry is one
	// draw here, not a fixed expectation.
	scheme := factory.GenerateRecordPayloadSizes(packet)
	out := make([]int, 0, len(scheme))
	for _, size := range scheme {
		if size == padding.CheckMark {
			out = append(out, 0)
			continue
		}
		out = append(out, size)
	}
	return out
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: anytls-oracle out.json")
		os.Exit(2)
	}
	factory := padding.NewPaddingFactory(padding.DefaultPaddingScheme)
	if factory == nil {
		fmt.Fprintln(os.Stderr, "built-in padding scheme did not parse")
		os.Exit(1)
	}
	password := sha256.Sum256([]byte(syntheticPassword))
	recordSizes := make([][]int, 0, 8)
	for packet := uint32(0); packet < 8; packet++ {
		recordSizes = append(recordSizes, sizes(factory, packet))
	}
	vector := vector{
		Name:             "sing-anytls-default",
		PaddingSchemeMD5: factory.Md5,
		PasswordSHA256:   hex.EncodeToString(password[:]),
		Stop:             factory.Stop,
		HelloPadding:     factory.GenerateRecordPayloadSizes(0)[0],
		RecordSizes:      recordSizes,
		SettingsPayload:  "client=sing-anytls/0.0.13\npadding-md5=" + factory.Md5 + "\nv=2",
		// command=Push(2), stream=1, length=2, payload "hi".
		FirstPushFrameHex: "020000000100026869",
		Notes: []string{
			"The reference draws record sizes from crypto/rand; RecordSizes here is a single draw, not a fixed expectation for a range entry.",
		},
	}
	encoded, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[1], append(encoded, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
