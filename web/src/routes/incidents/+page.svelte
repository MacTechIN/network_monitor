<script>
  import { onMount } from 'svelte';
  import { getJSON } from '$lib/api.js';
  import { sevLabel, shortTime } from '$lib/format.js';
  import Loader from '$lib/Loader.svelte';

  let rows = $state(null);
  let error = $state('');

  onMount(async () => {
    try {
      rows = await getJSON('/incidents');
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  });
</script>

<h1>사건</h1>
<Loader state={rows} {error} empty="묶인 사건이 없습니다(상관 엔진은 M4).">
  <table>
    <thead>
      <tr><th>생성</th><th>심각도</th><th>제목</th><th>상태</th></tr>
    </thead>
    <tbody>
      {#each rows as i (i.id)}
        <tr>
          <td class="mono">{shortTime(i.created_ts)}</td>
          <td>{sevLabel(i.severity)}</td>
          <td><a href="/incidents/{i.id}">{i.title ?? `사건 #${i.id}`}</a></td>
          <td>{i.status}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</Loader>
