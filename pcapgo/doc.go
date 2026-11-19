// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

/*
Package pcapgo provides some native PCAP support, not requiring C libpcap to be installed.

# Overview

This package contains implementations for native PCAP support. Currently supported are

  - pcap-files read/write: Reader, Writer
  - pcapng-files read/write: NgReader, NgWriter
  - raw socket capture (linux only): EthernetHandle

# Basic Usage pcapng

Pcapng files can be read and written. Reading supports both big and little endian files, packet blocks,
simple packet blocks, enhanced packets blocks, interface blocks, and interface statistics blocks. All
the options also by Wireshark are supported. The default reader options match libpcap behaviour. Have
a look at NgReaderOptions for more advanced usage. Both ReadPacketData and ZeroCopyReadPacketData is
supported (which means PacketDataSource and ZeroCopyPacketDataSource is supported).

	f, err := os.Open("somefile.pcapng")
	if err != nil {
		...
	}
	defer f.Close()

	r, err := NewNgReader(f, DefaultNgReaderOptions)
	if err != nil {
		...
	}

	data, ci, err := r.ReadPacketData()
	...

Write supports only little endian, enhanced packets blocks, interface blocks, and interface statistics
blocks. The same options as with writing are supported. Interface timestamp resolution is fixed to
10^-9s to match time.Time. Any other values are ignored. Upon creating a writer, a section, and an
interface block is automatically written. Additional interfaces can be added at any time. Since
the writer uses a bufio.Writer internally, Flush must be called before closing the file! Have a look
at NewNgWriterInterface for more advanced usage.

	f, err := os.Create("somefile.pcapng")
	if err != nil {
		...
	}
	defer f.Close()

	r, err = NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		...
	}
	defer r.Flush()

	err = r.WritePacket(ci, data)
	...

# Malformed And Truncated Capture Files

The readers treat lengths declared by the file as untrusted input and keep the
byte stream synchronized to the container format:

  - A classic pcap record whose CaptureLength runs past the snap length, past
    the original packet length, or past the end of the file is rejected. The
    classic Reader then returns io.EOF on every later call, so a Packets()
    range loop stops instead of reinterpreting the missing record's tail as
    another header. Lengths above the eager-read limit are grown with the
    bytes actually read, so a huge declared length in a tiny file cannot force
    a multi-gigabyte allocation.
  - A pcapng block is bounded by its block total length. ReadPacketData and
    ZeroCopyReadPacketData reject a packet block whose declared CaptureLength
    does not fit in the block before reading past its boundary, which keeps one
    corrupt block from being merged into a packet and desynchronizing every
    block that follows; a truncated block header or body surfaces as
    io.ErrUnexpectedEOF.
  - An unrecognized pcapng block type is skipped over its declared length, and
    an unknown pcap magic or version is rejected when the reader is opened.

gopacket.NewPacketSource turns these read errors into the end of the packet
channel; the layer decoders then apply their own truncation rules to the
frames that were read successfully (see the layers package documentation).
*/
package pcapgo
