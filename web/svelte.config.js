import adapter from '@sveltejs/adapter-static';

// SPA(클라이언트 렌더) 정적 빌드. FastAPI 가 build/ 를 StaticFiles 로 서빙한다(ADR-0002).
// Node 런타임은 상주하지 않는다.
/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    adapter: adapter({
      pages: 'build',
      assets: 'build',
      fallback: 'index.html',
      precompress: false,
      strict: true
    })
  }
};

export default config;
