// RFC 4253 §6 binary packet helpers used only by the packet-layer exhibits.
// The pre-existing handshake engine intentionally keeps its compact JSON model.

export const SSH_BLOCK_SIZE = 16;
export const SSH_MAC_SIZE = 32;
export const SSH_MAX_PACKET_LENGTH = 256 * 1024;

export interface EncodedPacket {
	packetLength: number;
	paddingLength: number;
	payload: Uint8Array;
	padding: Uint8Array;
	wire: Uint8Array;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
	let length = 0;
	for (const part of parts) length += part.length;
	const out = new Uint8Array(length);
	let offset = 0;
	for (const part of parts) {
		out.set(part, offset);
		offset += part.length;
	}
	return out;
}

export function uint32(value: number): Uint8Array {
	const out = new Uint8Array(4);
	new DataView(out.buffer).setUint32(0, value >>> 0, false);
	return out;
}

export function readUint32(bytes: Uint8Array, offset = 0): number {
	if (bytes.length < offset + 4) throw new Error('need four bytes for uint32');
	return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, false);
}

export function xorBytes(...parts: Uint8Array[]): Uint8Array {
	if (parts.length === 0) return new Uint8Array();
	const length = parts[0]!.length;
	if (parts.some((part) => part.length !== length)) throw new Error('XOR inputs must have equal length');
	const out = new Uint8Array(length);
	for (let i = 0; i < length; i++) {
		let value = 0;
		for (const part of parts) value ^= part[i]!;
		out[i] = value;
	}
	return out;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
	if (left.length !== right.length) return false;
	let difference = 0;
	for (let i = 0; i < left.length; i++) difference |= left[i]! ^ right[i]!;
	return difference === 0;
}

export function randomBytes(length: number): Uint8Array {
	return crypto.getRandomValues(new Uint8Array(length));
}

export function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
	const clean = hex.replace(/[^0-9a-f]/gi, '');
	if (clean.length % 2 !== 0) throw new Error('hex must contain whole bytes');
	const out = new Uint8Array(clean.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
	return out;
}

export function encodePacket(
	payload: Uint8Array,
	paddingSource: Uint8Array = randomBytes(SSH_BLOCK_SIZE * 2),
	blockSize = SSH_BLOCK_SIZE,
): EncodedPacket {
	if (blockSize < 8) throw new Error('SSH block size must be at least eight bytes');
	let paddingLength = blockSize - ((payload.length + 5) % blockSize);
	if (paddingLength < 4) paddingLength += blockSize;
	if (paddingSource.length < paddingLength) throw new Error('not enough padding bytes');
	const padding = paddingSource.slice(0, paddingLength);
	const packetLength = 1 + payload.length + paddingLength;
	const wire = concatBytes(uint32(packetLength), Uint8Array.of(paddingLength), payload, padding);
	if (wire.length % blockSize !== 0) throw new Error('packet is not block aligned');
	return { packetLength, paddingLength, payload: payload.slice(), padding, wire };
}

export function packetPayload(packet: Uint8Array): Uint8Array {
	const packetLength = readUint32(packet);
	if (packet.length !== packetLength + 4) throw new Error('packet length does not match wire bytes');
	const paddingLength = packet[4]!;
	if (paddingLength < 4 || paddingLength + 1 > packetLength) throw new Error('invalid SSH padding');
	return packet.slice(5, 4 + packetLength - paddingLength);
}

export function blocks(bytes: Uint8Array, blockSize = SSH_BLOCK_SIZE): Uint8Array[] {
	if (bytes.length % blockSize !== 0) throw new Error('input must contain whole blocks');
	const out: Uint8Array[] = [];
	for (let offset = 0; offset < bytes.length; offset += blockSize) {
		out.push(bytes.slice(offset, offset + blockSize));
	}
	return out;
}
