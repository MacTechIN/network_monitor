// API 는 같은 오리진의 상대경로로 호출한다(CORS 불필요, 인증은 Tailscale header 위임).
/** @param {string} path @returns {Promise<any>} */
export async function getJSON(path) {
  const res = await fetch(path, { headers: { accept: 'application/json' } });
  if (!res.ok) {
    throw new Error(`${path} → ${res.status}`);
  }
  return res.json();
}
