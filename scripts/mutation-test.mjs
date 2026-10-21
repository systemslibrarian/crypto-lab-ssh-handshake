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
		maxBuffer: 16 * 1024 * 1024,
		timeout: 180_000,
		env: { ...process.env, CI: '1' },
	});
	const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
	if (result.error || result.signal || result.status === null) {
		throw new Error(`${command} did not complete normally: ${result.error?.message ?? result.signal}`);
	}
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
	return ['playwright', 'test', 'tests/e2e/claims.spec.ts', '--grep', grep, '--retries=0', '--workers=1', '--reporter=json'];
}

function runClaims(grep, expectedStatus) {
	const result = run('npx', claimsArgs(grep), expectedStatus === 'passed' ? 'pass' : 'fail');
	let report;
	try {
		report = JSON.parse(result.stdout);
	} catch {
		throw new Error(`No valid Playwright JSON report for ${grep}:\n${result.output}`);
	}
	if (report.errors?.length) throw new Error(`Infrastructure error, not a mutation kill: ${JSON.stringify(report.errors)}`);
	const specs = [];
	const visit = (suite) => {
		specs.push(...(suite.specs ?? []));
		for (const child of suite.suites ?? []) visit(child);
	};
	for (const suite of report.suites ?? []) visit(suite);
	if (specs.length !== 1 || !specs[0].title.includes(grep)) {
		throw new Error(`Expected exactly the owning ${grep} test, got ${specs.map((spec) => spec.title).join(', ')}`);
	}
	const tests = specs[0].tests ?? [];
	if (tests.length !== 1 || tests[0].expectedStatus !== 'passed' || tests[0].results?.length !== 1) {
		throw new Error(`${grep}: missing, skipped, expected-failure, or retried test cannot prove a kill`);
	}
	const observed = tests[0].results[0];
	if (observed.status !== expectedStatus) {
		throw new Error(`${grep}: expected ${expectedStatus}, got ${observed.status}; timeouts are not kills`);
	}
	if (expectedStatus === 'failed' && !observed.errors?.some((error) =>
		/\bexpect\(|AssertionError/.test((error.message ?? '').replace(/\u001b\[[0-9;]*m/g, '')))) {
		throw new Error(`${grep}: failure was not an assertion about the named claim: ${JSON.stringify(observed.errors)}`);
	}
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
	runClaims(mutation.grep, 'passed');
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

		runClaims(mutation.grep, 'failed');
		console.log(`  4. NAMED test red (${mutation.grep})`);
	} finally {
		writeFileSync(sourcePath, original);
		run('npm', ['run', 'build']);
		runClaims(mutation.grep, 'passed');
		const restoredHash = bundleHash();
		if (restoredHash !== baselineHash) throw new Error(`${mutation.id}: restored bundle differs from baseline`);
		console.log('  5. restored and green');
	}
	results.push(mutation.id);
}

console.log(`\nMutation summary: ${results.length} of ${ledger.length} killed.`);
