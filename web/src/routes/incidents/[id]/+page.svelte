<script>
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { getJSON } from '$lib/api.js';
  import { sevLabel, shortTime } from '$lib/format.js';

  let item = $state(null);
  let error = $state('');

  onMount(async () => {
    try {
      item = await getJSON(`/incidents/${page.params.id}`);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  });
</script>

<p><a href="/incidents">← 사건 목록</a></p>
{#if error}
  <p class="err">불러오기 실패: {error}</p>
{:else if item === null}
  <p class="muted">불러오는 중…</p>
{:else}
  <h1>{item.title ?? `사건 #${item.id}`}</h1>
  <dl>
    <dt>생성</dt><dd class="mono">{shortTime(item.created_ts)}</dd>
    <dt>심각도</dt><dd>{sevLabel(item.severity)}</dd>
    <dt>상태</dt><dd>{item.status}</dd>
    <dt>기기</dt><dd class="mono">{item.device_key ?? '—'}</dd>
  </dl>
{/if}

<style>
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 6px 16px;
    max-width: 520px;
  }
  dt {
    color: #8a93a6;
  }
  dd {
    margin: 0;
  }
  .err {
    color: #ff8080;
  }
  .muted {
    color: #8a93a6;
  }
</style>
