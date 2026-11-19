// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package layers

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// This file pins down the strict side of the decode/reassembly contract.
//
// layers is strict: a layer whose declared lengths run past the captured
// bytes must return an error and call SetTruncated instead of slicing out of
// bounds. But decoding is also recoverable — the partial layer is still
// registered and every Payload it exposes stays inside the captured bytes, so
// a caller that chooses tolerance (tcpassembly being the prime example) can
// keep handling later layers and later packets.
//
// Unknown next-layer protocols take the other strictness knob: NewPacket
// reports them through ErrorLayer, while DecodingLayerParser offers
// IgnoreUnsupported for callers that want to stop cleanly without an error.

// edgeEthIP builds an Ethernet/IPv4 frame. proto is the IPv4 protocol number
// and transport is whatever follows the 20-byte IPv4 header.
func edgeEthIP(proto IPProtocol, transport []byte) []byte {
	frame := make([]byte, 14+20+len(transport))
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[14:34]
	ip[0] = 0x45
	total := 20 + len(transport)
	ip[2], ip[3] = byte(total>>8), byte(total)
	ip[8] = 64
	ip[9] = byte(proto)
	copy(frame[34:], transport)
	return frame
}

// edgeTCPHeader returns a 20-byte TCP header with the given data-offset words
// and no payload.
func edgeTCPHeader(dataOffsetWords int) []byte {
	h := make([]byte, 20)
	h[12] = byte(dataOffsetWords) << 4
	h[13] = 0x10 // ACK
	return h
}

// TestTruncatedTransportHeadersSetTruncated checks the layers end of the
// layers-vs-tcpassembly trade-off for the two transports a reassembler cares
// about. Each malformed input must come back as an error with the Truncated
// feedback flag, never as a panic, whether reached directly or via a packet.
func TestTruncatedTransportHeadersSetTruncated(t *testing.T) {
	cases := []struct {
		name    string
		decode  func([]byte, gopacket.DecodeFeedback) error
		data    []byte
		wantErr string
	}{
		{"tcp/header-below-minimum", (&TCP{}).DecodeFromBytes, make([]byte, 12), "Invalid TCP header"},
		{"tcp/data-offset-past-end", (&TCP{}).DecodeFromBytes, edgeTCPHeader(10), "TCP data offset"},
		{"udp/header-below-minimum", (&UDP{}).DecodeFromBytes, make([]byte, 6), "Invalid UDP header"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fb := &truncationFeedback{}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("decoder panicked on truncated input: %v", r)
					}
				}()
				if err := c.decode(c.data, fb); err == nil {
					t.Fatal("truncated input decoded without error")
				} else if c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), c.wantErr)
				}
			}()
			if !fb.truncated {
				t.Error("decoder returned an error without calling SetTruncated")
			}

			// Through NewPacket the same failure must be visible on the packet
			// metadata and as the error layer, with the TCP/UDP layer still
			// present for tolerant callers.
			var proto IPProtocol
			var layerType gopacket.LayerType
			switch c.name[:3] {
			case "tcp":
				proto, layerType = IPProtocolTCP, LayerTypeTCP
			case "udp":
				proto, layerType = IPProtocolUDP, LayerTypeUDP
			}
			p := gopacket.NewPacket(edgeEthIP(proto, c.data), LayerTypeEthernet, gopacket.Default)
			if !p.Metadata().Truncated {
				t.Error("packet metadata did not inherit the truncation flag")
			}
			if p.ErrorLayer() == nil {
				t.Fatal("packet has no error layer for the truncated transport")
			}
			if l := p.Layer(layerType); l == nil {
				t.Fatal("partial transport layer was not registered despite the error")
			}
		})
	}
}

// TestTruncatedTransportPayloadStaysInBounds proves the tolerant path is
// safe: the Payload exposed by a layer that saw a longer declared length than
// captured bytes is clipped to the captured bytes, so tcpassembly's
// copy(t.Payload) can never read past the frame.
func TestTruncatedTransportPayloadStaysInBounds(t *testing.T) {
	t.Run("udp", func(t *testing.T) {
		d := make([]byte, 12)
		d[4], d[5] = 0x00, 0x40 // claims 64 bytes
		u := &UDP{}
		fb := &truncationFeedback{}
		if err := u.DecodeFromBytes(d, fb); err != nil {
			t.Fatalf("UDP with an over-long declared length should stay decodable, got %v", err)
		}
		if !fb.truncated {
			t.Fatal("over-long UDP length did not flag truncation")
		}
		if got := len(u.LayerPayload()); got != 4 {
			t.Fatalf("UDP payload length %d, want the 4 in-bounds bytes (12 captured - 8 header)", got)
		}
	})

	t.Run("tcp", func(t *testing.T) {
		// Data offset claims 10 header words (40 bytes) but only 24 are present.
		d := edgeTCPHeader(10)
		d = append(d, 1, 2, 3, 4)
		tcp := &TCP{}
		fb := &truncationFeedback{}
		err := tcp.DecodeFromBytes(d, fb)
		if err == nil {
			t.Fatal("TCP with data offset past the buffer must error")
		}
		if !fb.truncated {
			t.Fatal("TCP over-long data offset did not flag truncation")
		}
		if len(tcp.LayerPayload()) != 0 {
			t.Fatalf("errored TCP layer exposes %d payload bytes, want none", len(tcp.LayerPayload()))
		}
	})
}

// TestUnknownProtocolStrictAndTolerant covers the unknown-protocol knob. The
// strict default surfaces the missing decoder; IgnoreUnsupported lets a parser
// stop cleanly with the layers it did decode and no error, which is the
// boundary a reassembly pipeline relies on when it only understands TCP.
func TestUnknownProtocolStrictAndTolerant(t *testing.T) {
	t.Run("new-packet-unknown-ethertype", func(t *testing.T) {
		frame := make([]byte, 18)
		frame[12], frame[13] = 0x99, 0x99
		p := gopacket.NewPacket(frame, LayerTypeEthernet, gopacket.Default)
		if p.ErrorLayer() == nil {
			t.Fatal("unknown ethertype produced no error layer")
		}
		// NewPacket wraps the decoder error in a DecodeFailure whose Error()
		// surfaces the underlying message; the wrapped type is not preserved.
		if !strings.Contains(p.ErrorLayer().Error().Error(), "Unable to decode EthernetType") {
			t.Fatalf("error layer %v does not report the unsupported ethertype", p.ErrorLayer())
		}
		if p.Layer(LayerTypeEthernet) == nil {
			t.Fatal("the decodable Ethernet layer must still be present")
		}
	})

	t.Run("parser-unregistered-ip-protocol", func(t *testing.T) {
		// IPv4 carrying protocol 253, whose enumeration has no registered
		// decoder: NextLayerType is LayerTypeZero and parsing stops cleanly
		// with the layers that did decode.
		frame := edgeEthIP(IPProtocol(253), []byte{1, 2, 3, 4})
		eth := &Ethernet{}
		ip := &IPv4{}
		parser := gopacket.NewDecodingLayerParser(LayerTypeEthernet, eth, ip)

		var decoded []gopacket.LayerType
		if err := parser.DecodeLayers(frame, &decoded); err != nil {
			t.Fatalf("an unregistered next layer should stop parsing, not error: %v", err)
		}
		want := []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4}
		if !layerTypesEqual(decoded, want) {
			t.Fatalf("decoded layers %v, want %v", decoded, want)
		}
	})

	t.Run("parser-registered-but-unprovided-decoder", func(t *testing.T) {
		// UDP is a registered, known layer type, but the parser was built
		// without a UDP decoder. This is the case that yields
		// UnsupportedLayerType; IgnoreUnsupported turns it into a clean stop.
		frame := edgeEthIP(IPProtocolUDP, []byte{0, 7, 0, 7, 0, 8, 0, 0})
		eth := &Ethernet{}
		ip := &IPv4{}
		parser := gopacket.NewDecodingLayerParser(LayerTypeEthernet, eth, ip)

		var decoded []gopacket.LayerType
		err := parser.DecodeLayers(frame, &decoded)
		if err == nil {
			t.Fatal("strict parser accepted a known layer type without a decoder")
		}
		var unsupported gopacket.UnsupportedLayerType
		if !errors.As(err, &unsupported) {
			t.Fatalf("error %v is not UnsupportedLayerType", err)
		}

		parser.IgnoreUnsupported = true
		decoded = nil
		if err := parser.DecodeLayers(frame, &decoded); err != nil {
			t.Fatalf("IgnoreUnsupported still returned an error: %v", err)
		}
		want := []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4}
		if !layerTypesEqual(decoded, want) {
			t.Fatalf("decoded layers %v, want %v", decoded, want)
		}
	})
}

// truncationFeedback records SetTruncated for direct DecodeFromBytes calls,
// mirroring what DecodingLayerParser and packet do internally.
type truncationFeedback struct{ truncated bool }

func (f *truncationFeedback) SetTruncated() { f.truncated = true }

func layerTypesEqual(got, want []gopacket.LayerType) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestICMPv6RDNSSShortOptionString covers a RDNSS option whose Data is too
// short for its lifetime field. The wire decoder rejects such an option, but a
// programmatically constructed one must still render through String() without
// an out-of-bounds panic, falling back to the hex form like the other guarded
// option types.
func TestICMPv6RDNSSShortOptionString(t *testing.T) {
	for _, n := range []int{0, 1, 2, 5} {
		opt := ICMPv6Option{Type: ICMPv6OptRecursiveDNSServer, Data: make([]byte, n)}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("RDNSS String() panicked on %d-byte Data: %v", n, r)
				}
			}()
			if got := opt.String(); got == "" {
				t.Fatalf("RDNSS String() returned empty for %d-byte Data", n)
			}
		}()
	}

	// A well-formed option (6-byte header + one 16-byte server) still renders
	// through the dedicated RDNSS branch rather than the hex fallback.
	server := net.ParseIP("2001:db8::1").To16()
	data := make([]byte, 6+16)
	binary.BigEndian.PutUint32(data[2:6], 300)
	copy(data[6:], server)
	good := ICMPv6Option{Type: ICMPv6OptRecursiveDNSServer, Data: data}
	if got := good.String(); !strings.Contains(got, "2001:db8::1") {
		t.Fatalf("well-formed RDNSS option rendered %q, want it to name the server", got)
	}
}
