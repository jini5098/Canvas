// 기본적인 오프라인 캐싱을 위한 서비스 워커
self.addEventListener('install', (e) => {
  console.log('[Service Worker] Install');
});
self.addEventListener('fetch', (e) => {
  // 현재는 통과만 시킴 (추후 오프라인 기능 추가 가능)
});