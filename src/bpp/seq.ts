export interface SequenceSnapshot {
	clientSend: number;
	clientReceive: number;
	serverSend: number;
	serverReceive: number;
}

export class SequenceCounters {
	clientSend = 0;
	clientReceive = 0;
	serverSend = 0;
	serverReceive = 0;

	clientToServer(): number {
		const sequence = this.clientSend;
		this.clientSend = (this.clientSend + 1) >>> 0;
		this.serverReceive = (this.serverReceive + 1) >>> 0;
		return sequence;
	}

	serverToClient(delivered = true): number {
		const sequence = this.serverSend;
		this.serverSend = (this.serverSend + 1) >>> 0;
		if (delivered) this.clientReceive = (this.clientReceive + 1) >>> 0;
		return sequence;
	}

	injectToClient(): number {
		const expected = this.clientReceive;
		this.clientReceive = (this.clientReceive + 1) >>> 0;
		return expected;
	}

	resetAfterClientNewKeys(): void {
		this.clientSend = 0;
		this.serverReceive = 0;
	}

	resetAfterServerNewKeys(): void {
		this.serverSend = 0;
		this.clientReceive = 0;
	}

	snapshot(): SequenceSnapshot {
		return {
			clientSend: this.clientSend,
			clientReceive: this.clientReceive,
			serverSend: this.serverSend,
			serverReceive: this.serverReceive,
		};
	}
}

export function countersBeforeNewKeys(): SequenceCounters {
	const counters = new SequenceCounters();
	counters.clientToServer(); // C KEXINIT
	counters.serverToClient(); // S KEXINIT
	counters.clientToServer(); // ECDH_INIT
	counters.serverToClient(); // ECDH_REPLY
	return counters;
}
