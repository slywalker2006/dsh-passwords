// 构建浏览器侧插件包：esbuild 把 src/client/* 打成 CJS，
// 再包成 dsh 客户端模块系统要求的 __ModuleLoader__.load 工厂格式
// （classic script + factory(require)）。
// 产物：dist/client.js（dsh 通过 /plugins/dsh-passwords/client.js 分发）。
import { build } from 'esbuild';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PACKAGE_ID = 'dsh-passwords';
// 产物固定写到包根 dist/：不依赖进程 cwd（从任意目录运行都能正确落盘）
const OUT_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'client.js');

const result = await build({
  entryPoints: ['src/client/index.tsx'],
  bundle: true,
  format: 'cjs',
  platform: 'browser',
  target: ['es2020'],
  jsx: 'automatic',
  minify: true,
  write: false,
  // 这些由 dsh 的客户端模块图提供（__ModuleLoader__ require 解析），不能打进包里；
  // react* 同理：dsh 前端把自己的 react 作为静态模块共享给所有插件（必须共用
  // 同一份 React，否则 hooks 在渲染器里拿不到 dispatcher 会直接崩溃）
  external: [
    // React 由 DSH 客户端模块表提供；其他 DSH imports 均为 type-only，
    // 已在 esbuild 阶段擦除，不应在产物中保留不存在的运行时入口。
    'react*',
  ],
  logLevel: 'info',
});

const code = result.outputFiles[0].text;
const wrapped = `window.__ModuleLoader__.load({
	id: ${JSON.stringify(PACKAGE_ID)},
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
${code}
		return module.exports;
	}
});
`;
writeFileSync(OUT_FILE, wrapped);
console.log('dist/client.js 构建完成');
