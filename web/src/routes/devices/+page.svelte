<script>
  import { onMount } from 'svelte';
  import { getJSON } from '$lib/api.js';
  import { shortTime } from '$lib/format.js';
  import Loader from '$lib/Loader.svelte';

  let rows = $state(null);
  let error = $state('');

  onMount(async () => {
    try {
      rows = await getJSON('/devices');
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  });
</script>

<h1>기기</h1>
<Loader state={rows} {error} empty="아직 발견된 기기가 없습니다.">
  <table>
    <thead>
      <tr><th>라벨</th><th>벤더</th><th>IP</th><th>MAC</th><th>랜덤</th><th>마지막</th></tr>
    </thead>
    <tbody>
      {#each rows as d (d.key)}
        <tr>
          <td>{d.label ?? '—'}</td>
          <td>{d.vendor ?? '—'}</td>
          <td>{d.ip ?? '—'}</td>
          <td class="mono">{d.mac ?? '—'}</td>
          <td>{d.randomized ? '예' : '아니오'}</td>
          <td class="mono">{shortTime(d.last_seen)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</Loader>
