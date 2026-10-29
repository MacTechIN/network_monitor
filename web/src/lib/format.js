// 심각도 숫자를 사람이 읽을 라벨로. Suricata severity 는 1(높음)~3(낮음) 관례.
/** @param {number | null | undefined} sev */
export function sevLabel(sev) {
  if (sev == null) return '—';
  return { 1: '높음', 2: '중간', 3: '낮음', 4: '정보', 5: '정보' }[sev] ?? String(sev);
}

/** @param {string | null | undefined} ts */
export function shortTime(ts) {
  if (!ts) return '—';
  return ts.replace('T', ' ').replace(/(\+00:00|Z)$/, '');
}
