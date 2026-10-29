<script>
  import { onMount } from 'svelte';
  import { getJSON } from '$lib/api.js';
  import { sevLabel, shortTime } from '$lib/format.js';
  import Loader from '$lib/Loader.svelte';

  let rows = $state(null);
  let error = $state('');

  onMount(async () => {
    try {
      rows = await getJSON('/alerts');
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  });
</script>

<h1>알림</h1>
<Loader state={rows} {error} empty="알림이 없습니다.">
  <table>
    <thead>
      <tr><th>시각</th><th>심각도</th><th>시그니처</th><th>출발→목적지</th><th>분류</th></tr>
    </thead>
    <tbody>
      {#each rows as a (a.id)}
        <tr>
          <td class="mono">{shortTime(a.ts)}</td>
          <td>{sevLabel(a.severity)}</td>
          <td>{a.signature ?? '—'}</td>
          <td class="mono">{a.src_ip ?? '?'} → {a.dest_ip ?? '?'}</td>
          <td>{a.category ?? '—'}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</Loader>
