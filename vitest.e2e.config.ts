import { defineConfig } from 'vitest/config';
import { config } from 'dotenv';
config({ path: '.e2e.env' });
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 60000,
    hookTimeout: 90000,
  },
});
