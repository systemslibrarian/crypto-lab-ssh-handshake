import { defineConfig } from 'vitest/config';

// Keep vitest scoped to src/ unit tests; playwright tests live in tests/e2e
// and are run via `npm run test:e2e`.
export default defineConfig({
	test: {
		include: ['src/**/*.test.ts'],
	},
});
