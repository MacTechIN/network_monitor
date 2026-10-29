<script>
  import { onMount } from 'svelte';
  import { getJSON } from '$lib/api.js';

  let status = $state('확인 중…');
  let counts = $state({ devices: 0, alerts: 0, incidents: 0 });

  onMount(async () => {
    try {
      const health = await getJSON('/healthz');
      status = health.status === 'ok' ? '정상' : health.status;
      const [devices, alerts, incidents] = await Promise.all([
        getJSON('/devices'),
        getJSON('/alerts'),
        getJSON('/incidents')
      ]);
      counts = { devices: devices.length, alerts: alerts.length, incidents: incidents.length };
    } catch (e) {
      status = `백엔드 연결 실패: ${e instanceof Error ? e.message : e}`;
    }
  });
</script>

<h1>개요</h1>
<p>백엔드: <strong>{status}</strong></p>
<ul>
  <li>기기 {counts.devices}대</li>
  <li>알림 {counts.alerts}건</li>
  <li>사건 {counts.incidents}건</li>
</ul>
<p>Tailscale 네트워크 내부에서만 접근합니다(인터넷 미노출).</p>
