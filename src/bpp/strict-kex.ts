export const STRICT_CLIENT = 'kex-strict-c-v00@openssh.com';
export const STRICT_SERVER = 'kex-strict-s-v00@openssh.com';

export interface StrictKexNegotiation {
	clientOffers: boolean;
	serverOffers: boolean;
	active: boolean;
}

export function negotiateStrictKex(clientOffers: boolean, serverOffers: boolean): StrictKexNegotiation {
	return { clientOffers, serverOffers, active: clientOffers && serverOffers };
}

export type InitialKexMessage = 'KEXINIT' | 'KEX' | 'NEWKEYS' | 'IGNORE';

export function checkInitialKexMessage(
	negotiation: StrictKexNegotiation,
	message: InitialKexMessage,
	messageIndex: number,
): { accepted: boolean; rule: string } {
	if (!negotiation.active) return { accepted: true, rule: 'strict kex is not active unless both peers offer it' };
	if (messageIndex === 0 && message !== 'KEXINIT') {
		return { accepted: false, rule: 'strict kex requires KEXINIT to be the first packet' };
	}
	if (message === 'IGNORE') {
		return { accepted: false, rule: 'strict kex terminates on a non-KEX message during initial key exchange' };
	}
	return { accepted: true, rule: 'message is permitted during strict initial key exchange' };
}
