(async function(){
  // fetch meta for brand link or repo if needed
  const res = await fetch('/api/meta');
  const meta = await res.json().catch(()=>({}));
  const hostBrand = 'Timeboard';
  const nav = `
    <div class="brand"><a href="/">{}hostBrand</a></div>
    <nav>
      <a href="/" data-path="/">Dashboard</a>
      <a href="/new" data-path="/new">New Task</a>
      <a href="/about" data-path="/about">About</a>
    </nav>`;
  const hdr = document.getElementById('header');
  if (hdr) { hdr.innerHTML = nav.replace('{}hostBrand', hostBrand); }
  // set active link
  const here = location.pathname;
  document.querySelectorAll('nav a[data-path]').forEach(a=>{
    if (a.getAttribute('data-path')===here) a.classList.add('active');
  });
  // draw subheader search bar if container exists
  const sub = document.getElementById('subheader');
  if (sub) {
    sub.innerHTML = `<input id="search" placeholder="Search name:foo type:bar tag:baz" />`;
  }
})();
