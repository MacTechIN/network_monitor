<script>
  // 간단한 데이터 로더: 로딩/에러/빈 상태를 공통 처리한다.
  let { state, error, empty = '데이터가 없습니다.', children } = $props();
</script>

{#if error}
  <p class="err">불러오기 실패: {error}</p>
{:else if state === null}
  <p class="muted">불러오는 중…</p>
{:else if Array.isArray(state) && state.length === 0}
  <p class="muted">{empty}</p>
{:else}
  {@render children()}
{/if}

<style>
  .err {
    color: #ff8080;
  }
  .muted {
    color: #8a93a6;
  }
</style>
