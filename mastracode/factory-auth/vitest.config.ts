import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'unit:mastra-factory-auth',
    environment: 'node',
    include: ['src/**/*.test.ts'],
    exclude: ['**/node_modules/**', '**/dist/**'],
    // The EE boundary test walks @mastra/core's source graph, which is large.
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
