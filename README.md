# tiny-tcp-pseudo-header

Computes the TCP or UDP checksum over a segment buffer using the IPv4 or IPv6 pseudo header.

```js
import { tcpChecksum, udpChecksum } from "tiny-tcp-pseudo-header";

const segment = new Uint8Array([
  0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
]);

const tcp = tcpChecksum({
  source: "192.0.2.1",
  destination: "198.51.100.7",
  segment,
});

const udp = udpChecksum({
  source: "192.0.2.1",
  destination: "198.51.100.7",
  segment,
});
```

Both functions return a 16-bit unsigned integer. They do not write it into the segment; the caller owns the segment layout and decides where the checksum field lives.

## Why this exists

The TCP and UDP checksums cover more than the segment itself. They also cover a pseudo header built from the IP source address, destination address, protocol or next-header value, and the segment length. That pseudo header is not adjacent to the segment in memory, so a checksum routine that only walks the segment will produce a value the receiver rejects.

The trade-off here is scope. This library builds pseudo headers and folds checksums, but it does not parse IP or TCP headers, does not verify received packets, and does not write the result back into a buffer. Parsing and writing depend on the packet representation a caller already has, and guessing at one would be worse than leaving it out. Callers with a parsed packet pass the addresses and the segment bytes; callers building a packet pass the same values before transmission.

The IPv6 pseudo header is 40 bytes and uses a 32-bit length field, while the IPv4 pseudo header is 12 bytes with a 16-bit length. Both are produced by the exported builders if you want to inspect or reuse them; `tcpChecksum` and `udpChecksum` build the IPv4 form for you.

## Exports

- `pseudoHeaderIPv4({ source, destination, protocol, length })` returns the 12-byte IPv4 pseudo header.
- `pseudoHeaderIPv6({ source, destination, nextHeader, length })` returns the 40-byte IPv6 pseudo header.
- `onesComplementSum(buffers)` returns the unfolded 32-bit Internet checksum sum over an array of byte buffers.
- `checksum(pseudoHeader, segment)` returns the folded 16-bit checksum over two buffers.
- `tcpChecksum({ source, destination, segment })` builds the IPv4 pseudo header with protocol 6 and returns the TCP checksum.
- `udpChecksum({ source, destination, segment })` builds the IPv4 pseudo header with protocol 17, returns the UDP checksum, and maps a computed zero to `0xffff` as RFC 768 requires.
- `PseudoHeaderError` is thrown for malformed addresses, non-byte values, and lengths that do not fit their field.

Addresses may be dotted-quad strings, four-byte buffers, or arrays of byte values. IPv6 addresses may be the full eight-group form, the `::` compressed form, or a form with an embedded IPv4 tail such as `::ffff:192.0.2.1`.

## The awkward edge

An odd-length buffer pads its final byte with a zero low byte, and that padding applies per buffer, not to the concatenation. If you split an odd-length segment across two calls to `onesComplementSum`, the result differs from summing it in one call. Pass the pseudo header and the segment as separate buffers, as the exported functions do, and the padding is applied correctly to each; do not pre-split the segment into arbitrary chunks unless each chunk is even-length.

Also note that a computed UDP checksum of zero is transmitted as `0xffff`. `udpChecksum` applies that rule, but `checksum` does not, because `checksum` is also used for TCP where zero is a legal transmitted value.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

