import { defineConfig } from 'vitest/config';
import { config } from 'dotenv';

// Load .env file
config();

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 60000,
    hookTimeout: 60000,  // Match test timeout
  },
});
