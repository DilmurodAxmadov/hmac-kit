import { defineConfig } from 'tsup';

/**
 * Build configuration for `@daxmadov/hmac-kit`.
 *
 * We produce a *multi-entry* build so that each public subpath in
 * `package.json#exports` ships its own minimal bundle. This means a consumer
 * who only imports `@daxmadov/hmac-kit/client` does NOT pull in server code,
 * Redis store, NestJS guard, etc. — keeping cold-start size and surface area
 * minimal.
 *
 * Dual ESM (`.js`) + CJS (`.cjs`) output is generated for Node.js compat.
 */
export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'client/index': 'src/client/index.ts',
    'server/index': 'src/server/index.ts',
    'adapters/express': 'src/adapters/express.ts',
    'adapters/nestjs': 'src/adapters/nestjs.ts',
    'adapters/fastify': 'src/adapters/fastify.ts',
    'edge/index': 'src/edge/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  minify: false,
  target: 'node18',
  // Peer-dep packages must NEVER be bundled; users provide them.
  external: ['ioredis', 'express', 'fastify', '@nestjs/common', 'rxjs'],
  outExtension: ({ format }) => ({
    js: format === 'cjs' ? '.cjs' : '.js',
  }),
});
