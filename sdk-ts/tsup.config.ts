import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  sourcemap: true,
  shims: true,
  clean: true,
  splitting: false,
  minify: true,
});
