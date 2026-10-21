// AES-CTR comparison for APW: the same captured CBC block is processed at an
// unrelated counter position, so its first four plaintext bytes are unrelated
// to the target block.

export async function aesCtrTransform(
	key: Uint8Array,
	counter: Uint8Array,
	input: Uint8Array,
): Promise<Uint8Array> {
	if (key.length !== 16) throw new Error('AES-128 needs a 16-byte key');
	if (counter.length !== 16) throw new Error('AES-CTR counter must be 16 bytes');
	const cryptoKey = await crypto.subtle.importKey(
		'raw',
		key.buffer as ArrayBuffer,
		{ name: 'AES-CTR' },
		false,
		['encrypt'],
	);
	const output = await crypto.subtle.encrypt(
		{ name: 'AES-CTR', counter: counter.buffer as ArrayBuffer, length: 64 },
		cryptoKey,
		input.buffer as ArrayBuffer,
	);
	return new Uint8Array(output);
}
