<script>
  let { children } = $props();
  const nav = [
    { href: '/', label: '개요' },
    { href: '/devices', label: '기기' },
    { href: '/alerts', label: '알림' },
    { href: '/incidents', label: '사건' }
  ];
</script>

<div class="shell">
  <header>
    <strong>netmon</strong>
    <nav>
      {#each nav as item (item.href)}
        <a href={item.href}>{item.label}</a>
      {/each}
    </nav>
  </header>
  <main>
    {@render children()}
  </main>
</div>

<style>
  :global(body) {
    margin: 0;
    font-family: system-ui, sans-serif;
    background: #0f1115;
    color: #e6e6e6;
  }
  .shell {
    max-width: 960px;
    margin: 0 auto;
    padding: 0 16px;
  }
  header {
    display: flex;
    align-items: baseline;
    gap: 16px;
    padding: 16px 0;
    border-bottom: 1px solid #2a2f3a;
  }
  nav {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
  }
  nav a {
    color: #9db4ff;
    text-decoration: none;
  }
  main {
    padding: 16px 0;
  }
  :global(table) {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }
  :global(th),
  :global(td) {
    text-align: left;
    padding: 8px 10px;
    border-bottom: 1px solid #2a2f3a;
  }
  :global(th) {
    color: #8a93a6;
    font-weight: 600;
  }
  :global(.mono) {
    font-family: ui-monospace, monospace;
  }
  :global(a) {
    color: #9db4ff;
  }
</style>
