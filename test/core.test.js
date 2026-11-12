import test from "node:test";
import assert from "node:assert/strict";

import {
  PseudoHeaderError,
  pseudoHeaderIPv4,
  pseudoHeaderIPv6,
  onesComplementSum,
  checksum,
  tcpChecksum,
  udpChecksum,
} from "../src/index.js";

// Build the canonical IPv4 TCP segment used in several tests. The header is a
// minimal 20-byte TCP header with a zero checksum field; the payload is short
// so the expected value is easy to reason about by hand.
function sampleTcpSegment() {
  return new Uint8Array([
    0x30, 0x39, // source port 12345
    0x00, 0x50, // destination port 80
    0x00, 0x00, 0x00, 0x01, // sequence number 1
    0x00, 0x00, 0x00, 0x00, // ack number 0
    0x50, 0x02, // data offset 5, SYN
    0x20, 0x00, // window 8192
    0x00, 0x00, // checksum placeholder
    0x00, 0x00, // urgent pointer
    0xde, 0xad, 0xbe, 0xef, // payload
  ]);
}

test("pseudoHeaderIPv4 lays out fields in network order", () => {
  const ph = pseudoHeaderIPv4({
    source: "192.0.2.1",
    destination: "198.51.100.7",
    protocol: 6,
    length: 24,
  });
  assert.equal(ph.length, 12);
  assert.deepEqual(Array.from(ph), [
    192, 0, 2, 1,
    198, 51, 100, 7,
    0, 6,
    0, 24,
  ]);
});

test("pseudoHeaderIPv4 accepts byte arrays and rejects bad lengths", () => {
  const ph = pseudoHeaderIPv4({
    source: [10, 0, 0, 1],
    destination: [10, 0, 0, 2],
    protocol: 17,
    length: 0x1234,
  });
  assert.deepEqual(Array.from(ph.slice(8)), [0, 17, 0x12, 0x34]);
  assert.throws(
    () =>
      pseudoHeaderIPv4({
        source: [10, 0, 0],
        destination: [10, 0, 0, 2],
        protocol: 17,
        length: 8,
      }),
    PseudoHeaderError,
  );
  assert.throws(
    () =>
      pseudoHeaderIPv4({
        source: "10.0.0.1",
        destination: "10.0.0.2",
        protocol: 17,
        length: 0x10000,
      }),
    PseudoHeaderError,
  );
});

test("ipv4 string parsing rejects leading zeros and out-of-range octets", () => {
  assert.throws(
    () =>
      pseudoHeaderIPv4({
        source: "10.0.0.01",
        destination: "10.0.0.2",
        protocol: 6,
        length: 0,
      }),
    PseudoHeaderError,
  );
  assert.throws(
    () =>
      pseudoHeaderIPv4({
        source: "10.0.0.256",
        destination: "10.0.0.2",
        protocol: 6,
        length: 0,
      }),
    PseudoHeaderError,
  );
});

test("pseudoHeaderIPv6 expands the compressed form", () => {
  const ph = pseudoHeaderIPv6({
    source: "2001:db8::1",
    destination: "2001:db8::2",
    nextHeader: 6,
    length: 20,
  });
  assert.equal(ph.length, 40);
  assert.deepEqual(Array.from(ph.slice(0, 4)), [0x20, 0x01, 0x0d, 0xb8]);
  assert.deepEqual(Array.from(ph.slice(16, 20)), [0x20, 0x01, 0x0d, 0xb8]);
  assert.deepEqual(Array.from(ph.slice(32)), [0, 0, 0, 20, 0, 0, 0, 6]);
});

test("pseudoHeaderIPv6 accepts an embedded IPv4 tail", () => {
  const ph = pseudoHeaderIPv6({
    source: "::ffff:192.0.2.1",
    destination: "::ffff:198.51.100.7",
    nextHeader: 17,
    length: 8,
  });
  assert.deepEqual(Array.from(ph.slice(0, 16)), [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1,
  ]);
  assert.equal(ph[39], 17);
});

test("pseudoHeaderIPv6 rejects malformed addresses", () => {
  for (const bad of ["2001:db8:::1", "2001:db8::1::2", "2001:db8::gg"]) {
    assert.throws(
      () =>
        pseudoHeaderIPv6({
          source: bad,
          destination: "::1",
          nextHeader: 6,
          length: 0,
        }),
      PseudoHeaderError,
    );
  }
});

test("onesComplementSum handles odd lengths per buffer", () => {
  // 0x0102 + 0x0300 (odd trailing byte padded with zero low byte) = 0x0402
  const sum = onesComplementSum([new Uint8Array([1, 2, 3])]);
  assert.equal(sum, 0x0402);
  // Each odd buffer is padded with a zero low byte, so the two 0xff bytes
  // contribute 0xff00 each and the carries fold into 0xfe01.
  const split = onesComplementSum([new Uint8Array([0xff]), new Uint8Array([0xff])]);
  assert.equal(split, 0xfe01);
});

test("onesComplementSum folds carries", () => {
  const sum = onesComplementSum([
    new Uint8Array([0xff, 0xff, 0xff, 0xff]),
  ]);
  // 0xffff + 0xffff = 0x1fffe -> fold -> 0xffff
  assert.equal(sum, 0xffff);
});

test("checksum returns the one's complement of the folded sum", () => {
  // Sum of 0x0001 is 1, complement is 0xfffe.
  assert.equal(checksum(new Uint8Array([0x00, 0x01]), new Uint8Array(0)), 0xfffe);
  // All-zero input complements to 0xffff.
  assert.equal(checksum(new Uint8Array(0), new Uint8Array(0)), 0xffff);
});

test("tcpChecksum matches a hand-computed IPv4 example", () => {
  const segment = sampleTcpSegment();
  const value = tcpChecksum({
    source: "192.0.2.1",
    destination: "198.51.100.7",
    segment,
  });
  // Recompute independently by summing the pseudo header and segment words.
  const ph = pseudoHeaderIPv4({
    source: "192.0.2.1",
    destination: "198.51.100.7",
    protocol: 6,
    length: segment.length,
  });
  let sum = 0;
  for (const buf of [ph, segment]) {
    let i = 0;
    for (; i + 1 < buf.length; i += 2) {
      sum += (buf[i] << 8) | buf[i + 1];
      sum = (sum & 0xffff) + (sum >>> 16);
    }
    if (i < buf.length) {
      sum += buf[i] << 8;
      sum = (sum & 0xffff) + (sum >>> 16);
    }
  }
  const expected = ~((sum & 0xffff) + (sum >>> 16)) & 0xffff;
  assert.equal(value, expected);
  assert.notEqual(value, 0);
});

test("udpChecksum maps a zero result to 0xffff", () => {
  // Find a segment whose computed checksum over the loopback pair is zero,
  // then confirm udpChecksum maps it to 0xffff per RFC 768.
  const source = "127.0.0.1";
  const destination = "127.0.0.1";
  let zeroSegment = null;
  for (let word = 0; word <= 0xffff; word += 1) {
    const candidate = new Uint8Array([(word >> 8) & 0xff, word & 0xff]);
    if (checksum(pseudoHeaderIPv4({
      source,
      destination,
      protocol: 17,
      length: candidate.length,
    }), candidate) === 0) {
      zeroSegment = candidate;
      break;
    }
  }
  assert.notEqual(zeroSegment, null);
  const value = udpChecksum({ source, destination, segment: zeroSegment });
  assert.equal(value, 0xffff);
});

test("tcpChecksum rejects oversized IPv4 segments", () => {
  assert.throws(
    () =>
      tcpChecksum({
        source: "10.0.0.1",
        destination: "10.0.0.2",
        segment: new Uint8Array(0x10000),
      }),
    PseudoHeaderError,
  );
});

test("checksum does not mutate its inputs", () => {
  const segment = sampleTcpSegment();
  const copy = Uint8Array.from(segment);
  tcpChecksum({ source: "192.0.2.1", destination: "198.51.100.7", segment });
  assert.deepEqual(Array.from(segment), Array.from(copy));
});

// A segment that already contains a valid checksum must sum to zero across the
// pseudo header and segment, which is the property receivers rely on.
test("a valid TCP checksum makes the full sum fold to 0xffff", () => {
  const segment = sampleTcpSegment();
  const value = tcpChecksum({
    source: "192.0.2.1",
    destination: "198.51.100.7",
    segment,
  });
  segment[16] = (value >> 8) & 0xff;
  segment[17] = value & 0xff;
  const ph = pseudoHeaderIPv4({
    source: "192.0.2.1",
    destination: "198.51.100.7",
    protocol: 6,
    length: segment.length,
  });
  assert.equal(checksum(ph, segment), 0x0000);
});
