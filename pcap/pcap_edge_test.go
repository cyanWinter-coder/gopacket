// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package pcap

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// This file covers malformed capture files at the pcap boundary: a valid
// global header followed by a truncated record, and a header cut short. The
// reader must report a read error and then stay closed (io.EOF on every later
// read) rather than resynchronizing onto payload bytes and handing a
// half-record to the layer decoders.

// pcapGlobalHeader writes a little-endian classic pcap global header with the
// given snapshot length and Ethernet link type.
func pcapGlobalHeader(snaplen uint32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:4], 0xA1B2C3D4) // microsecond magic
	binary.LittleEndian.PutUint16(b[4:6], 2)          // major
	binary.LittleEndian.PutUint16(b[6:8], 4)          // minor
	binary.LittleEndian.PutUint32(b[16:20], snaplen)
	binary.LittleEndian.PutUint32(b[20:24], 1) // Ethernet
	return b
}

// pcapRecordHeader writes a 16-byte per-record header claiming capLen bytes.
func pcapRecordHeader(capLen, origLen uint32) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[8:12], capLen)
	binary.LittleEndian.PutUint32(b[12:16], origLen)
	return b
}

func writeTempPcap(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "edge.pcap")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestOpenOfflineTruncatedGlobalHeader: a file ending inside the 24-byte
// global header cannot be opened.
func TestOpenOfflineTruncatedGlobalHeader(t *testing.T) {
	path := writeTempPcap(t, pcapGlobalHeader(65535)[:16])
	handle, err := OpenOffline(path)
	if err == nil {
		handle.Close()
		t.Fatal("truncated global header was accepted")
	}
}

// TestOpenOfflineUnknownMagic keeps the existing "unknown file format"
// contract explicit for the boundary documentation.
func TestOpenOfflineUnknownMagic(t *testing.T) {
	path := writeTempPcap(t, []byte{0xAB, 0xAD, 0x1D, 0xEA, 0, 0, 0, 0, 0, 0, 0, 0})
	handle, err := OpenOffline(path)
	if err == nil {
		handle.Close()
		t.Fatal("unknown magic was accepted")
	}
}

// TestTruncatedRecordReadIsFinal opens a file whose first record promises 32
// payload bytes but supplies only 8, then verifies the read error is final:
// every subsequent read returns io.EOF so a Packets() loop terminates instead
// of interpreting the missing tail as a new record.
func TestTruncatedRecordReadIsFinal(t *testing.T) {
	file := pcapGlobalHeader(65535)
	file = append(file, pcapRecordHeader(32, 32)...)
	file = append(file, 1, 2, 3, 4, 5, 6, 7, 8) // only 8 of the 32 claimed
	path := writeTempPcap(t, file)

	handle, err := OpenOffline(path)
	if err != nil {
		t.Fatalf("valid global header should open: %v", err)
	}
	defer handle.Close()

	if _, _, err := handle.ReadPacketData(); err == nil {
		t.Fatal("truncated record returned no error")
	}
	if _, _, err := handle.ReadPacketData(); err != io.EOF {
		t.Errorf("read after truncation: got %v, want io.EOF", err)
	}
	if _, _, err := handle.ZeroCopyReadPacketData(); err != io.EOF {
		t.Errorf("zero-copy read after truncation: got %v, want io.EOF", err)
	}
}
