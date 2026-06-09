// sshfp.ts — toy SSHFP DNS registry. The honest model: SSHFP closes the
// first-contact gap ONLY if the DNS lookup goes through a trusted channel —
// DNSSEC in real life. Without DNSSEC, an attacker who controls DNS can serve
// their own fingerprint and the "out-of-band verification" lies to the user.

export interface SshfpRecord {
	hostName: string;
	fingerprint: string;       // SHA256:... matching ssh-keygen -lf
	dnssecSigned: boolean;     // toggled to demonstrate the bootstrap-trust gap
	publishedAt: string;
}

// One process-wide registry. In a real network this would be the zone file at
// the host's DNS provider.
const registry = new Map<string, SshfpRecord>();

export function publishSshfp(hostName: string, fingerprint: string, dnssecSigned = true): SshfpRecord {
	const rec: SshfpRecord = {
		hostName,
		fingerprint,
		dnssecSigned,
		publishedAt: new Date().toISOString(),
	};
	registry.set(hostName, rec);
	return rec;
}

export function lookupSshfp(hostName: string): SshfpRecord | undefined {
	return registry.get(hostName);
}

export function removeSshfp(hostName: string): boolean {
	return registry.delete(hostName);
}

export function clearSshfp(): void {
	registry.clear();
}

// Simulate a DNS-spoofing attacker who installs their OWN fingerprint at the
// host's name. Reproduces "SSHFP without DNSSEC is no protection" honestly.
export function poisonSshfp(hostName: string, attackerFingerprint: string): SshfpRecord {
	return publishSshfp(hostName, attackerFingerprint, /* dnssecSigned */ false);
}

export type SshfpVerdict =
	| { kind: 'no-record'; reason: string }
	| { kind: 'mismatch'; record: SshfpRecord; presented: string }
	| { kind: 'match'; record: SshfpRecord }
	| { kind: 'match-unsigned'; record: SshfpRecord };

export function verifySshfp(hostName: string, presentedFingerprint: string): SshfpVerdict {
	const rec = registry.get(hostName);
	if (!rec) {
		return {
			kind: 'no-record',
			reason: `No SSHFP record published for ${hostName} — fall back to TOFU or verify out of band manually.`,
		};
	}
	if (rec.fingerprint !== presentedFingerprint) {
		return { kind: 'mismatch', record: rec, presented: presentedFingerprint };
	}
	if (!rec.dnssecSigned) {
		return { kind: 'match-unsigned', record: rec };
	}
	return { kind: 'match', record: rec };
}
