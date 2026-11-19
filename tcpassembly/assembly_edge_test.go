// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package tcpassembly

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// This file pins down the boundary between strict layer decoding and the
// tolerant stream reassembler when malformed input meets a timing event:
//
//   - layers.DecodeFromBytes rejects a truncated segment with an error and a
//     SetTruncated flag, while still registering the partial layer, so the
//     Packet and Flow interfaces keep their existing shape.
//   - An Assembler never re-validates a *layers.TCP it is handed: the caller
//     decides whether an errored packet is fed in. Feeding the partial layer
//     must stay in-bounds, and skipping it must not poison the stream.
//   - A FlushOlderThan timeout while gaps are open delivers the queued pages
//     with Skip markers and closes the stream without merging the gap.
//
// The tests build full Ethernet/IPv4/TCP frames so they exercise the same
// gopacket.NewPacket -> Layer(LayerTypeTCP) -> Assemble path real capture
// loops use, rather than constructing reassembler structs directly.

// edgeStream records every callback in order.
type edgeStream struct {
	factory *edgeFactory
	bytes   []byte
	skips   []int
	ends    int
	done    bool
}

func (s *edgeStream) Reassembled(rs []Reassembly) {
	for _, r := range rs {
		if r.Skip != 0 {
			s.skips = append(s.skips, r.Skip)
		}
		s.bytes = append(s.bytes, r.Bytes...)
		if r.End {
			s.ends++
		}
	}
}

func (s *edgeStream) ReassemblyComplete() {
	s.done = true
}

type edgeFactory struct{ streams []*edgeStream }

func (f *edgeFactory) New(netFlow, tcpFlow gopacket.Flow) Stream {
	s := &edgeStream{factory: f}
	f.streams = append(f.streams, s)
	return s
}

func (f *edgeFactory) single(t *testing.T) *edgeStream {
	t.Helper()
	if len(f.streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(f.streams))
	}
	return f.streams[0]
}

// edgeFrame is a minimal Ethernet/IPv4/TCP frame builder. Payload nil means
// "no payload"; truncate drops bytes off the end to simulate a capture cut
// short inside the TCP header.
type edgeFrame struct {
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
	seq, ack         uint32
	flags            uint8 // FIN, SYN, RST, PSH, ACK bits per the TCP layout
	payload          []byte
	truncate         int
}

func (f edgeFrame) bytes(t *testing.T) []byte {
	t.Helper()
	tcpLen := uint16(20 + len(f.payload))
	ipLen := uint16(20) + tcpLen
	eth := make([]byte, 14+20+tcpLen)
	// Ethernet: broadcast-ish dst/src, IPv4 ethertype.
	eth[12], eth[13] = 0x08, 0x00
	ip := eth[14:34]
	ip[0] = 0x45
	ip[2], ip[3] = byte(ipLen>>8), byte(ipLen)
	ip[8] = 64 // TTL
	ip[9] = 6  // TCP
	copy(ip[12:16], f.srcIP.To4())
	copy(ip[16:20], f.dstIP.To4())
	tcp := eth[34:]
	tcp[0], tcp[1] = byte(f.srcPort>>8), byte(f.srcPort)
	tcp[2], tcp[3] = byte(f.dstPort>>8), byte(f.dstPort)
	tcp[4], tcp[5], tcp[6], tcp[7] = byte(f.seq>>24), byte(f.seq>>16), byte(f.seq>>8), byte(f.seq)
	tcp[8], tcp[9], tcp[10], tcp[11] = byte(f.ack>>24), byte(f.ack>>16), byte(f.ack>>8), byte(f.ack)
	tcp[12] = 5 << 4 // data offset 5 words
	tcp[13] = f.flags
	tcp[14], tcp[15] = 0xff, 0xff // window
	if f.payload != nil {
		copy(tcp[20:], f.payload)
	}
	if f.truncate > 0 {
		if f.truncate > len(eth) {
			t.Fatalf("truncate %d exceeds frame length %d", f.truncate, len(eth))
		}
		eth = eth[:len(eth)-f.truncate]
	}
	return eth
}

func (f edgeFrame) decode(t *testing.T) gopacket.Packet {
	t.Helper()
	p := gopacket.NewPacket(f.bytes(t), layers.LayerTypeEthernet, gopacket.Default)
	return p
}

const (
	edgeFIN = 0x01
	edgeSYN = 0x02
	edgeRST = 0x04
	edgePSH = 0x08
	edgeACK = 0x10
)

var (
	edgeSrcIP = net.IP{10, 0, 0, 1}
	edgeDstIP = net.IP{10, 0, 0, 2}
)

func edgeNetFlow(t *testing.T) gopacket.Flow {
	t.Helper()
	nf, err := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(edgeSrcIP),
		layers.NewIPEndpoint(edgeDstIP))
	if err != nil {
		t.Fatal(err)
	}
	return nf
}

// feedTCP extracts the TCP layer the way capture loops do and hands it to the
// assembler, reporting whether the packet itself carried a decode error.
func feedTCP(a *Assembler, nf gopacket.Flow, p gopacket.Packet) (fed bool, decodeErr error) {
	if e := p.ErrorLayer(); e != nil {
		decodeErr = e.Error()
	}
	if l := p.Layer(layers.LayerTypeTCP); l != nil {
		a.Assemble(nf, l.(*layers.TCP))
		fed = true
	}
	return
}

// feedTCPStrict mirrors a capture loop that drops packets whose decoder
// reported an error: the partial TCP layer registered by AddLayer is looked up
// but never handed to the assembler.
func feedTCPStrict(a *Assembler, nf gopacket.Flow, p gopacket.Packet) (fed bool, decodeErr error) {
	if e := p.ErrorLayer(); e != nil {
		return false, e.Error()
	}
	if l := p.Layer(layers.LayerTypeTCP); l != nil {
		a.Assemble(nf, l.(*layers.TCP))
		fed = true
	}
	return
}

// TestTruncatedSegmentIsRejectedByLayers drives a frame cut short inside the
// TCP header through the full decoder. The layer decoder must flag the packet
// truncated and return an error, while still exposing the partial TCP layer so
// the Packet interface is unchanged for callers that inspect it.
func TestTruncatedSegmentIsRejectedByLayers(t *testing.T) {
	frame := edgeFrame{
		srcIP: edgeSrcIP, dstIP: edgeDstIP,
		srcPort: 1234, dstPort: 80, seq: 1000,
		flags: edgePSH | edgeACK, payload: []byte("hello"),
		// Drop the payload plus 8 header bytes, leaving 12 of the 20-byte header.
		truncate: 13,
	}
	p := frame.decode(t)
	if !p.Metadata().Truncated {
		t.Error("truncated packet did not set Metadata().Truncated")
	}
	if p.ErrorLayer() == nil {
		t.Fatal("truncated TCP header produced no decode error")
	}
	tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		t.Fatal("partial TCP layer missing after a truncation error")
	}
	// The partial layer carries no payload: nothing can be read past the frame.
	if len(tcp.LayerPayload()) != 0 {
		t.Errorf("partial TCP layer exposes %d payload bytes, want 0", len(tcp.LayerPayload()))
	}
}

// TestTruncatedSegmentDoesNotCorruptStream is the tolerant-continuation half
// of the trade-off. A capture loop that skips errored packets, then keeps
// feeding the healthy ones, must get the healthy bytes in order and be able to
// close the stream normally.
func TestTruncatedSegmentDoesNotCorruptStream(t *testing.T) {
	fact := &edgeFactory{}
	a := NewAssembler(NewStreamPool(fact))
	nf := edgeNetFlow(t)

	syn := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 1234, dstPort: 80, seq: 1000, flags: edgeSYN}
	if _, err := feedTCP(a, nf, syn.decode(t)); err != nil {
		t.Fatalf("SYN decode error: %v", err)
	}

	// Segment 1001..1006 arrives truncated. The caller checks the decode error
	// and refuses to feed the partial layer to the assembler.
	bad := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 1234, dstPort: 80, seq: 1001, flags: edgePSH | edgeACK, payload: []byte("hello"), truncate: 7}
	fed, err := feedTCPStrict(a, nf, bad.decode(t))
	if err == nil {
		t.Fatal("truncated segment decoded without error")
	}
	if fed {
		t.Fatal("strict feed handed an errored packet to the assembler")
	}

	// The next healthy segment, contiguous with the SYN's nextSeq (1001), is
	// delivered straight through. This proves skipping the bad packet left no
	// queued state behind.
	good := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 1234, dstPort: 80, seq: 1001, flags: edgePSH | edgeACK, payload: []byte("world")}
	if _, err := feedTCP(a, nf, good.decode(t)); err != nil {
		t.Fatalf("healthy segment decode error: %v", err)
	}
	fin := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 1234, dstPort: 80, seq: 1006, flags: edgeFIN | edgeACK}
	if _, err := feedTCP(a, nf, fin.decode(t)); err != nil {
		t.Fatalf("FIN decode error: %v", err)
	}

	s := fact.single(t)
	if got := string(s.bytes); got != "world" {
		t.Errorf("stream bytes = %q, want %q", got, "world")
	}
	if !s.done {
		t.Error("stream was not completed by the FIN after the skipped segment")
	}
}

// TestTruncatedPartialLayerFedToAssemblerStaysInBounds covers the other
// caller choice: some pipelines feed every TCP layer unconditionally. The
// partial layer has an empty payload, so the assembler must simply ignore it
// (no SYN/FIN/RST, no data) and keep the stream usable.
func TestTruncatedPartialLayerFedToAssemblerStaysInBounds(t *testing.T) {
	fact := &edgeFactory{}
	a := NewAssembler(NewStreamPool(fact))
	nf := edgeNetFlow(t)

	syn := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 1234, dstPort: 80, seq: 1000, flags: edgeSYN}
	a.Assemble(nf, syn.decode(t).Layer(layers.LayerTypeTCP).(*layers.TCP))

	bad := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 1234, dstPort: 80, seq: 1001, flags: edgePSH | edgeACK, payload: []byte("hello"), truncate: 13}
	p := bad.decode(t)
	if p.ErrorLayer() == nil {
		t.Fatal("expected a decode error on the truncated frame")
	}
	// Feed it anyway, as an unconditional pipeline would.
	a.Assemble(nf, p.Layer(layers.LayerTypeTCP).(*layers.TCP))

	good := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 1234, dstPort: 80, seq: 1001, flags: edgePSH | edgeACK, payload: []byte("world")}
	a.Assemble(nf, good.decode(t).Layer(layers.LayerTypeTCP).(*layers.TCP))

	s := fact.single(t)
	if got := string(s.bytes); got != "world" {
		t.Errorf("stream bytes = %q, want %q; the empty partial segment must be ignored", got, "world")
	}
}

// TestUnknownProtocolNeverReachesAssembler verifies the unknown-protocol half
// of the boundary: a frame whose ethertype has no decoder produces an
// UnsupportedLayer-style error and no TCP layer, so the capture loop's
// Layer(LayerTypeTCP) lookup returns nil and the assembler is never touched.
func TestUnknownProtocolNeverReachesAssembler(t *testing.T) {
	fact := &edgeFactory{}
	a := NewAssembler(NewStreamPool(fact))
	nf := edgeNetFlow(t)

	// Unknown ethertype 0x9999 with an arbitrary payload.
	raw := make([]byte, 18)
	raw[12], raw[13] = 0x99, 0x99
	raw[14], raw[15], raw[16], raw[17] = 1, 2, 3, 4
	p := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	if p.ErrorLayer() == nil {
		t.Fatal("unknown ethertype decoded without an error")
	}
	fed, _ := feedTCP(a, nf, p)
	if fed {
		t.Fatal("a frame with no TCP layer was fed to the assembler")
	}
	if len(fact.streams) != 0 {
		t.Fatalf("unknown protocol created %d streams, want 0", len(fact.streams))
	}

	// A normal TCP stream on the same assembler still works: unknown input left
	// no state that could be merged into a later, valid flow.
	syn := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 1234, dstPort: 80, seq: 7, flags: edgeSYN}
	a.Assemble(nf, syn.decode(t).Layer(layers.LayerTypeTCP).(*layers.TCP))
	data := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 1234, dstPort: 80, seq: 8, flags: edgePSH | edgeACK, payload: []byte("ok")}
	a.Assemble(nf, data.decode(t).Layer(layers.LayerTypeTCP).(*layers.TCP))
	s := fact.single(t)
	if got := string(s.bytes); got != "ok" {
		t.Errorf("stream after unknown-protocol input = %q, want %q", got, "ok")
	}
}

// TestTimeoutFlushWhileGapOpen combines the three failure modes. A gap opens
// (the middle segment is lost), out-of-order bytes queue behind it, and the
// flush timeout fires before the gap is filled: the queued bytes must be
// delivered with a Skip marker rather than merged at the wrong offset, and the
// stale connection must be closed exactly once.
func TestTimeoutFlushWhileGapOpen(t *testing.T) {
	fact := &edgeFactory{}
	a := NewAssembler(NewStreamPool(fact))
	nf := edgeNetFlow(t)
	base := time.Unix(1000, 0)

	syn := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 1234, dstPort: 80, seq: 1000, flags: edgeSYN}
	a.AssembleWithTimestamp(nf, syn.decode(t).Layer(layers.LayerTypeTCP).(*layers.TCP), base)

	// Segment covering seq 1010..1015 arrives first: it opens a nine-byte gap
	// (1001..1009) and must be queued, not delivered.
	later := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 1234, dstPort: 80, seq: 1010, flags: edgePSH | edgeACK, payload: []byte("later")}
	a.AssembleWithTimestamp(nf, later.decode(t).Layer(layers.LayerTypeTCP).(*layers.TCP), base.Add(time.Second))

	s := fact.single(t)
	if len(s.bytes) != 0 {
		t.Fatalf("out-of-order segment delivered early: %q", s.bytes)
	}

	// Flush everything older than the queued page. The gap is reported via Skip
	// and the queued bytes follow in stream order.
	flushed, closed := a.FlushOlderThan(base.Add(2 * time.Second))
	if flushed != 1 || closed != 1 {
		t.Fatalf("FlushOlderThan returned flushed=%d closed=%d, want 1/1", flushed, closed)
	}
	if got := string(s.bytes); got != "later" {
		t.Errorf("flushed bytes = %q, want %q", got, "later")
	}
	if len(s.skips) != 1 || s.skips[0] <= 0 {
		t.Errorf("gap skip markers = %v, want one positive Skip", s.skips)
	}
	if !s.done {
		t.Error("stale connection was not closed by the timeout flush")
	}

	// The late, gap-filling segment arrives after the close. It must open a
	// fresh stream rather than being merged into the completed one; without a
	// SYN it waits in that stream until a flush delivers it with a Skip marker.
	late := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 1234, dstPort: 80, seq: 1001, flags: edgePSH | edgeACK, payload: []byte("early")}
	a.AssembleWithTimestamp(nf, late.decode(t).Layer(layers.LayerTypeTCP).(*layers.TCP), base.Add(3*time.Second))
	if len(fact.streams) != 2 {
		t.Fatalf("late segment produced %d streams, want a new one instead of merging", len(fact.streams))
	}
	a.FlushAll()
	if got := string(fact.streams[1].bytes); got != "early" {
		t.Errorf("new stream bytes = %q, want %q", got, "early")
	}
	if len(fact.streams[1].skips) != 1 || fact.streams[1].skips[0] != -1 {
		t.Errorf("new stream skip markers = %v, want a single Skip -1 for the unseen prefix", fact.streams[1].skips)
	}
}

// TestTimeoutAndTruncationTogether is the simultaneous case. The gap-filling
// segment is truncated and skipped by the caller, while the timeout flush
// independently drains the queued page: neither event must panic or cause the
// two data sets to be concatenated out of order.
func TestTimeoutAndTruncationTogether(t *testing.T) {
	fact := &edgeFactory{}
	a := NewAssembler(NewStreamPool(fact))
	nf := edgeNetFlow(t)
	base := time.Unix(2000, 0)

	syn := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 4321, dstPort: 443, seq: 5000, flags: edgeSYN}
	a.AssembleWithTimestamp(nf, syn.decode(t).Layer(layers.LayerTypeTCP).(*layers.TCP), base)

	queued := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 4321, dstPort: 443, seq: 5010, flags: edgePSH | edgeACK, payload: []byte("queued")}
	a.AssembleWithTimestamp(nf, queued.decode(t).Layer(layers.LayerTypeTCP).(*layers.TCP), base.Add(time.Second))

	// The gap filler arrives truncated. Calling code drops it on the decode
	// error, so the assembler only ever sees the timeout path.
	filler := edgeFrame{srcIP: edgeSrcIP, dstIP: edgeDstIP, srcPort: 4321, dstPort: 443, seq: 5001, flags: edgePSH | edgeACK, payload: []byte("filler!!"), truncate: 9}
	p := filler.decode(t)
	if p.ErrorLayer() == nil || !p.Metadata().Truncated {
		t.Fatal("truncated gap filler was not flagged")
	}
	if l := p.Layer(layers.LayerTypeTCP); l != nil && len(l.(*layers.TCP).LayerPayload()) != 0 {
		t.Fatal("truncated gap filler unexpectedly carries payload")
	}

	flushed, closed := a.FlushOlderThan(base.Add(2 * time.Second))
	if flushed != 1 || closed != 1 {
		t.Fatalf("flush returned flushed=%d closed=%d, want 1/1", flushed, closed)
	}
	s := fact.single(t)
	if got := string(s.bytes); got != "queued" {
		t.Errorf("flushed stream = %q, want only the queued bytes", got)
	}
	if !s.done {
		t.Error("stream stayed open after the timeout")
	}
}
