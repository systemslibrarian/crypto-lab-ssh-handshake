import './style.css';
import './extra.css';
import { SshClient, SshServer, makeMitm } from './engine.ts';
import { mountApp } from './ui.ts';

// Dev-only self-test. Verifies the two headline behaviors: first connect to a
// fresh server succeeds and pins (TOFU), and a subsequent connect through a
// MITM responder is rejected because the pinned fingerprint changed.
if (import.meta.env.DEV) {
	console.group('crypto-lab-ssh-handshake: engine self-test');
	void (async () => {
		try {
			const server = await SshServer.create('server.example.com');
			const client = new SshClient();
			const first = await client.connect('server.example.com', server);
			const firstOk = first.connected && first.hostKeyDecision === 'tofu-pinned';
			console.log('First connect TOFU pinned:', firstOk, first.summary);
			if (!firstOk) console.error('SELF-TEST FAIL: first connect should pin via TOFU.');

			const attacker = await makeMitm('server.example.com');
			const mitm = await client.connect('server.example.com', attacker);
			const mitmOk = !mitm.connected && mitm.hostKeyDecision === 'CHANGED-REJECTED';
			console.log('MITM after pin rejected:', mitmOk, mitm.summary);
			if (!mitmOk) console.error('SELF-TEST FAIL: MITM after pin should be rejected.');
		} catch (err) {
			console.error('self-test threw:', err);
		} finally {
			console.groupEnd();
		}
	})();
}

mountApp(document.querySelector<HTMLDivElement>('#app')!);

(function initThemeToggle() {
	const button = document.getElementById('theme-toggle') as HTMLButtonElement | null;
	if (!button) return;

	function apply(theme: string): void {
		document.documentElement.setAttribute('data-theme', theme);
		localStorage.setItem('theme', theme);
		const isDark = theme === 'dark';
		button!.textContent = isDark ? '\u{1F319}' : '☀️';
		button!.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
	}

	const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
	apply(current);

	button.addEventListener('click', () => {
		const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
		apply(next);
	});
})();
