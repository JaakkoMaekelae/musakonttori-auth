import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'hq-authz/index': 'src/hq-authz/index.ts',
    'impersonation/index': 'src/impersonation/index.ts',
    'accounts/index': 'src/accounts/index.ts',
    'api-key/index': 'src/api-key/index.ts',
  },
  format: ['esm'],
  dts: true,
  sourcemap: true,
  external: ['jose'],
  clean: true,
  outDir: 'dist',
});
