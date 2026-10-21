// Attacker-side Terrapin operations. These functions can insert or remove only
// public wire packets; they have no access to keys, plaintext, or cipher code.

export interface WirePacket {
	kind: 'NEWKEYS' | 'EXT_INFO' | 'APPLICATION';
	sequence: number;
	wire: Uint8Array;
}

export interface ClearWireMessage {
	kind: 'SSH_MSG_IGNORE';
	wire: Uint8Array;
}

export function makeIgnoreWire(): ClearWireMessage {
	// RFC 4253 §11.2: message number 2, followed by an SSH string. The attack
	// needs only a syntactically valid cleartext message before NEWKEYS.
	return {
		kind: 'SSH_MSG_IGNORE',
		wire: Uint8Array.of(2, 0, 0, 0, 0),
	};
}

export function deleteExtInfo(packets: readonly WirePacket[]): {
	delivered: WirePacket[];
	deleted: WirePacket | null;
} {
	const index = packets.findIndex((packet) => packet.kind === 'EXT_INFO');
	if (index < 0) return { delivered: packets.map(clonePacket), deleted: null };
	return {
		delivered: packets.filter((_, packetIndex) => packetIndex !== index).map(clonePacket),
		deleted: clonePacket(packets[index]!),
	};
}

function clonePacket(packet: WirePacket): WirePacket {
	return { ...packet, wire: packet.wire.slice() };
}
