// tiny-tcp-pseudo-header
//
// Computes the TCP or UDP checksum over a segment buffer, including the IPv4 or
// IPv6 pseudo header. The pseudo header exists because TCP and UDP checksums
// cover not only their own segment but also a few fields from the IP header
// (source/destination address, protocol, and length). Those fields are not
// contiguous with the segment in memory, so the standard approach is to sum
// them separately and fold the two sums together.
//
// Design decision: this module is pure and buffer-oriented. It never touches
// sockets, never allocates per-call beyond the returned number, and never
// mutates the caller's segment. Callers that need to write the checksum into
// the segment do so themselves; that keeps the responsibility for the segment
// layout with the code that owns it.

/**
 * Error thrown when the inputs cannot describe a valid pseudo header.
 * A dedicated class lets callers distinguish bad-argument errors from
 * unrelated runtime failures without string matching.
 */
export class PseudoHeaderError extends Error {
  /**
   * @param {string} message
   */
  constructor(message) {
    super(message);
    this.name = "PseudoHeaderError";
  }
}

const IPV4_ADDR_LEN = 4;
const IPV6_ADDR_LEN = 16;

/**
 * Coerce a value to a Uint8Array without copying when possible.
 *
 * We accept plain arrays and ArrayBuffers because callers frequently build
 * headers from literals, and forcing a copy at every call site is noisy.
 * A Uint8Array view is returned so the summing code has a single fast path.
 *
 * @param {Uint8Array|ArrayBuffer|number[]} value
 * @param {string} label
 * @returns {Uint8Array}
 */
function toBytes(value, label) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (Array.isArray(value)) {
    // Validate each element so a typo like 256 or -1 fails loudly here rather
    // than silently wrapping during the byte read.
    const out = new Uint8Array(value.length);
    for (let i = 0; i < value.length; i += 1) {
      const b = value[i];
      if (!Number.isInteger(b) || b < 0 || b > 0xff) {
        throw new PseudoHeaderError(
          `${label}[${i}] is not a byte: ${String(b)}`,
        );
      }
      out[i] = b;
    }
    return out;
  }
  throw new PseudoHeaderError(
    `${label} must be a Uint8Array, ArrayBuffer, or number[]`,
  );
}

/**
 * Validate an IPv4 address and return it as four bytes.
 *
 * We accept the dotted-quad string form because that is what humans write,
 * and a 4-byte buffer because that is what a packet parser already has. Both
 * are unambiguous, so there is no need to guess.
 *
 * @param {string|Uint8Array|number[]} address
 * @returns {Uint8Array}
 */
function ipv4Bytes(address) {
  if (typeof address === "string") {
    const parts = address.split(".");
    if (parts.length !== IPV4_ADDR_LEN) {
      throw new PseudoHeaderError(`invalid IPv4 address: ${address}`);
    }
    const out = new Uint8Array(IPV4_ADDR_LEN);
    for (let i = 0; i < IPV4_ADDR_LEN; i += 1) {
      const part = parts[i];
      // Reject empty strings and leading-zero forms like "01": the former is
      // simply not a number, the latter is ambiguous and usually a bug.
      if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) {
        throw new PseudoHeaderError(`invalid IPv4 address: ${address}`);
      }
      const n = Number(part);
      if (n > 255) {
        throw new PseudoHeaderError(`invalid IPv4 address: ${address}`);
      }
      out[i] = n;
    }
    return out;
  }
  const bytes = toBytes(address, "ipv4 address");
  if (bytes.length !== IPV4_ADDR_LEN) {
    throw new PseudoHeaderError(
      `IPv4 address must be ${IPV4_ADDR_LEN} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

/**
 * Validate an IPv6 address and return it as sixteen bytes.
 *
 * Only the full eight-group hex form and the `::` compressed form are
 * accepted. A single embedded IPv4 tail (e.g. `::ffff:1.2.3.4`) is also
 * accepted because it is common in dual-stack captures and has an
 * unambiguous byte encoding. Anything else is rejected rather than guessed.
 *
 * @param {string|Uint8Array|number[]} address
 * @returns {Uint8Array}
 */
function ipv6Bytes(address) {
  if (typeof address !== "string") {
    const bytes = toBytes(address, "ipv6 address");
    if (bytes.length !== IPV6_ADDR_LEN) {
      throw new PseudoHeaderError(
        `IPv6 address must be ${IPV6_ADDR_LEN} bytes, got ${bytes.length}`,
      );
    }
    return bytes;
  }

  const out = new Uint8Array(IPV6_ADDR_LEN);
  let text = address;

  // An embedded IPv4 tail is only legal in the last 32 bits, so split it off
  // before doing the group parsing and convert it to two hex groups.
  const lastColon = text.lastIndexOf(":");
  if (lastColon !== -1 && text.slice(lastColon + 1).includes(".")) {
    const v4 = ipv4Bytes(text.slice(lastColon + 1));
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    text = `${text.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const doubleColon = text.indexOf("::");
  if (doubleColon !== -1 && text.indexOf("::", doubleColon + 1) !== -1) {
    throw new PseudoHeaderError(`invalid IPv6 address: ${address}`);
  }

  let head;
  let tail;
  if (doubleColon === -1) {
    head = text.split(":");
    tail = [];
  } else {
    const headText = text.slice(0, doubleColon);
    const tailText = text.slice(doubleColon + 2);
    head = headText === "" ? [] : headText.split(":");
    tail = tailText === "" ? [] : tailText.split(":");
  }

  const groups = head.concat(tail);
  if (doubleColon === -1 && groups.length !== 8) {
    throw new PseudoHeaderError(`invalid IPv6 address: ${address}`);
  }
  if (doubleColon !== -1 && groups.length > 7) {
    throw new PseudoHeaderError(`invalid IPv6 address: ${address}`);
  }

  const values = [];
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
      throw new PseudoHeaderError(`invalid IPv6 address: ${address}`);
    }
    values.push(parseInt(group, 16));
  }

  const missing = 8 - values.length;
  const expanded = [];
  for (let i = 0; i < head.length; i += 1) {
    expanded.push(values[i]);
  }
  for (let i = 0; i < missing; i += 1) {
    expanded.push(0);
  }
  for (let i = 0; i < tail.length; i += 1) {
    expanded.push(values[head.length + i]);
  }

  for (let i = 0; i < IPV6_ADDR_LEN / 2; i += 1) {
    const group = expanded[i];
    out[i * 2] = (group >> 8) & 0xff;
    out[i * 2 + 1] = group & 0xff;
  }
  return out;
}

/**
 * Build the 12-byte IPv4 pseudo header described by RFC 793 (TCP) and RFC 768
 * (UDP): source address, destination address, zero byte, protocol byte, and
 * the 16-bit segment length.
 *
 * @param {object} opts
 * @param {string|Uint8Array|number[]} opts.source
 * @param {string|Uint8Array|number[]} opts.destination
 * @param {number} opts.protocol IP protocol number (6 for TCP, 17 for UDP)
 * @param {number} opts.length Segment length in bytes, excluding the pseudo header
 * @returns {Uint8Array} 12 bytes
 */
export function pseudoHeaderIPv4(opts) {
  if (opts === null || typeof opts !== "object") {
    throw new PseudoHeaderError("pseudoHeaderIPv4 requires an options object");
  }
  const { source, destination, protocol, length } = opts;
  const src = ipv4Bytes(source);
  const dst = ipv4Bytes(destination);
  if (!Number.isInteger(protocol) || protocol < 0 || protocol > 0xff) {
    throw new PseudoHeaderError(`protocol must be a byte, got ${String(protocol)}`);
  }
  if (!Number.isInteger(length) || length < 0 || length > 0xffff) {
    throw new PseudoHeaderError(`length must fit in 16 bits, got ${String(length)}`);
  }

  const out = new Uint8Array(12);
  out.set(src, 0);
  out.set(dst, 4);
  out[8] = 0;
  out[9] = protocol;
  out[10] = (length >> 8) & 0xff;
  out[11] = length & 0xff;
  return out;
}

/**
 * Build the 40-byte IPv6 pseudo header described by RFC 2460: source address,
 * destination address, 32-bit upper-layer packet length, three zero bytes,
 * and the next-header byte.
 *
 * Note the length field is 32 bits here, unlike IPv4's 16 bits. We accept any
 * non-negative safe integer and mask it into four bytes; callers with a real
 * packet will always be far below that range.
 *
 * @param {object} opts
 * @param {string|Uint8Array|number[]} opts.source
 * @param {string|Uint8Array|number[]} opts.destination
 * @param {number} opts.nextHeader Next-header value (6 for TCP, 17 for UDP)
 * @param {number} opts.length Upper-layer packet length in bytes
 * @returns {Uint8Array} 40 bytes
 */
export function pseudoHeaderIPv6(opts) {
  if (opts === null || typeof opts !== "object") {
    throw new PseudoHeaderError("pseudoHeaderIPv6 requires an options object");
  }
  const { source, destination, nextHeader, length } = opts;
  const src = ipv6Bytes(source);
  const dst = ipv6Bytes(destination);
  if (!Number.isInteger(nextHeader) || nextHeader < 0 || nextHeader > 0xff) {
    throw new PseudoHeaderError(
      `nextHeader must be a byte, got ${String(nextHeader)}`,
    );
  }
  if (!Number.isInteger(length) || length < 0 || length > 0xffffffff) {
    throw new PseudoHeaderError(
      `length must fit in 32 bits, got ${String(length)}`,
    );
  }

  const out = new Uint8Array(40);
  out.set(src, 0);
  out.set(dst, 16);
  out[32] = (length >>> 24) & 0xff;
  out[33] = (length >>> 16) & 0xff;
  out[34] = (length >>> 8) & 0xff;
  out[35] = length & 0xff;
  out[36] = 0;
  out[37] = 0;
  out[38] = 0;
  out[39] = nextHeader;
  return out;
}

/**
 * Sum a sequence of byte buffers using the Internet 16-bit one's complement
 * sum, returning the raw 32-bit accumulator before folding.
 *
 * The odd-length case is the classic trap: if a buffer has an odd number of
 * bytes, the final byte is treated as the high byte of a 16-bit word with a
 * zero low byte. We handle that per buffer rather than concatenating, so
 * callers can pass several buffers without an extra copy.
 *
 * @param {Array<Uint8Array|ArrayBuffer|number[]>} buffers
 * @returns {number} unsigned 32-bit sum
 */
export function onesComplementSum(buffers) {
  if (!Array.isArray(buffers)) {
    throw new PseudoHeaderError("onesComplementSum expects an array of buffers");
  }
  let sum = 0;
  for (let i = 0; i < buffers.length; i += 1) {
    const bytes = toBytes(buffers[i], `buffers[${i}]`);
    let j = 0;
    for (; j + 1 < bytes.length; j += 2) {
      sum += (bytes[j] << 8) | bytes[j + 1];
      // Fold periodically so the accumulator cannot drift into a range where
      // JavaScript's float addition loses integer precision.
      sum = (sum & 0xffff) + (sum >>> 16);
    }
    if (j < bytes.length) {
      sum += bytes[j] << 8;
      sum = (sum & 0xffff) + (sum >>> 16);
    }
  }
  return sum >>> 0;
}

/**
 * Fold a 32-bit accumulator into the 16-bit one's complement checksum.
 *
 * @param {number} sum
 * @returns {number} 16-bit unsigned checksum
 */
function fold(sum) {
  let s = sum;
  while (s >>> 16) {
    s = (s & 0xffff) + (s >>> 16);
  }
  return (~s) & 0xffff;
}

/**
 * Compute the checksum over a pseudo header plus a segment buffer.
 *
 * @param {Uint8Array|ArrayBuffer|number[]} pseudoHeader
 * @param {Uint8Array|ArrayBuffer|number[]} segment
 * @returns {number} 16-bit unsigned checksum, ready to place in the segment
 */
export function checksum(pseudoHeader, segment) {
  const ph = toBytes(pseudoHeader, "pseudoHeader");
  const seg = toBytes(segment, "segment");
  return fold(onesComplementSum([ph, seg]));
}

/**
 * Compute the TCP checksum for a segment over IPv4.
 *
 * @param {object} opts
 * @param {string|Uint8Array|number[]} opts.source
 * @param {string|Uint8Array|number[]} opts.destination
 * @param {Uint8Array|ArrayBuffer|number[]} opts.segment
 * @returns {number}
 */
export function tcpChecksum(opts) {
  if (opts === null || typeof opts !== "object") {
    throw new PseudoHeaderError("tcpChecksum requires an options object");
  }
  const { source, destination, segment } = opts;
  const seg = toBytes(segment, "segment");
  if (seg.length > 0xffff) {
    throw new PseudoHeaderError(
      `TCP segment too long for IPv4: ${seg.length} bytes`,
    );
  }
  const ph = pseudoHeaderIPv4({
    source,
    destination,
    protocol: 6,
    length: seg.length,
  });
  return checksum(ph, seg);
}

/**
 * Compute the UDP checksum for a datagram over IPv4.
 *
 * Zero is a legal computed value but is transmitted as 0xFFFF for UDP, since
 * a zero checksum means "not computed" on the wire. We apply that rule here
 * because returning zero would silently disable verification.
 *
 * @param {object} opts
 * @param {string|Uint8Array|number[]} opts.source
 * @param {string|Uint8Array|number[]} opts.destination
 * @param {Uint8Array|ArrayBuffer|number[]} opts.segment
 * @returns {number}
 */
export function udpChecksum(opts) {
  if (opts === null || typeof opts !== "object") {
    throw new PseudoHeaderError("udpChecksum requires an options object");
  }
  const { source, destination, segment } = opts;
  const seg = toBytes(segment, "segment");
  if (seg.length > 0xffff) {
    throw new PseudoHeaderError(
      `UDP datagram too long for IPv4: ${seg.length} bytes`,
    );
  }
  const ph = pseudoHeaderIPv4({
    source,
    destination,
    protocol: 17,
    length: seg.length,
  });
  const value = checksum(ph, seg);
  return value === 0 ? 0xffff : value;
}
