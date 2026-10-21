import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const ledger = JSON.parse(readFileSync(resolve(root, 'tests/mutations/ledger.json'), 'utf8'));

function run(command, args, expectation = 'pass') {
	const result = spawnSync(command, args, {
		cwd: root,
		encoding: 'utf8',
		stdio: 'pipe',
		env: { ...process.env, CI: '1' },
	});
	const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
	if (expectation === 'pass' && result.status !== 0) {
		throw new Error(`${command} ${args.join(' ')} failed unexpectedly:\n${output}`);
	}
	if (expectation === 'fail' && result.status === 0) {
		throw new Error(`${command} ${args.join(' ')} passed, so the mutant survived`);
	}
	return { ...result, output };
}

function bundleHash() {
	const assets = resolve(root, 'dist/assets');
	const files = readdirSync(assets).filter((name) => name.endsWith('.js')).sort();
	const hash = createHash('sha256');
	for (const file of files) hash.update(readFileSync(resolve(assets, file)));
	return hash.digest('hex');
}

function claimsArgs(grep) {
	return ['playwright', 'test', 'tests/e2e/claims.spec.ts', '--grep', grep, '--retries=0', '--workers=1'];
}

const results = [];

for (const mutation of ledger) {
	const sourcePath = resolve(root, mutation.source);
	const original = readFileSync(sourcePath, 'utf8');
	if (original.split(mutation.find).length !== 2) {
		throw new Error(`${mutation.id}: mutation anchor must occur exactly once`);
	}
	const clean = run('git', ['diff', '--quiet', 'HEAD', '--', mutation.source], 'any');
	if (clean.status !== 0) throw new Error(`${mutation.id}: source is not clean against HEAD`);

	console.log(`\n[${mutation.id}] ${mutation.verdict}`);
	run('npx', claimsArgs(mutation.grep));
	run('npm', ['run', 'build']);
	const baselineHash = bundleHash();
	console.log('  1. baseline passes');

	try {
		writeFileSync(sourcePath, original.replace(mutation.find, mutation.replace));
		const diff = run('git', ['diff', '--', mutation.source]).output;
		if (!diff.trim()) throw new Error(`${mutation.id}: source diff is empty`);
		console.log('  2. source diff NON-EMPTY');

		run('npm', ['run', 'build']);
		const mutantHash = bundleHash();
		if (mutantHash === baselineHash) throw new Error(`${mutation.id}: production bundle hash did not move`);
		console.log(`  3. bundle hash MOVED (${baselineHash.slice(0, 12)} → ${mutantHash.slice(0, 12)})`);

		const killed = run('npx', claimsArgs(mutation.grep), 'fail');
		if (!killed.output.includes(mutation.grep)) {
			throw new Error(`${mutation.id}: a test failed, but not the named ${mutation.grep} test`);
		}
		console.log(`  4. NAMED test red (${mutation.grep})`);
	} finally {
		writeFileSync(sourcePath, original);
	}

	run('npm', ['run', 'build']);
	run('npx', claimsArgs(mutation.grep));
	const restoredHash = bundleHash();
	if (restoredHash !== baselineHash) throw new Error(`${mutation.id}: restored bundle differs from baseline`);
	console.log('  5. restored and green');
	results.push(mutation.id);
}

console.log(`\nMutation summary: ${results.length} of ${ledger.length} killed.`);
