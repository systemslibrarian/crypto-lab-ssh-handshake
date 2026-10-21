/// <reference lib="webworker" />

interface RateRequest {
	attempts: number;
	seed: number;
}

interface RateProgress {
	type: 'progress' | 'done';
	completed: number;
	attempts: number;
	fourteenBitHits: number;
	thirtyTwoBitHits: number;
}

const worker = self as unknown as DedicatedWorkerGlobalScope;

worker.addEventListener('message', (event: MessageEvent<RateRequest>) => {
	const attempts = Math.max(1, Math.floor(event.data.attempts));
	let state = event.data.seed >>> 0;
	let fourteenBitHits = 0;
	let thirtyTwoBitHits = 0;
	const chunk = 131_072;
	let completed = 0;

	const runChunk = (): void => {
		const end = Math.min(completed + chunk, attempts);
		for (; completed < end; completed++) {
			state ^= state << 13;
			state ^= state >>> 17;
			state ^= state << 5;
			const length = state >>> 0;
			if (length >= 5 && length <= 256 * 1024) {
				fourteenBitHits++;
				if ((4 + length - 16) % 16 === 0) thirtyTwoBitHits++;
			}
		}
		const result: RateProgress = {
			type: completed === attempts ? 'done' : 'progress',
			completed,
			attempts,
			fourteenBitHits,
			thirtyTwoBitHits,
		};
		worker.postMessage(result);
		if (completed < attempts) setTimeout(runChunk, 0);
	};

	runChunk();
});

export {};
