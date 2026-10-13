const qs = (id) => document.getElementById(id);

async function postJSON(url, body){
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  return res.json().then((j)=> ({ok: res.ok, status: res.status, json: j})).catch(()=> ({ok: res.ok, status: res.status, json: null}));
}

qs('regBtn').addEventListener('click', async ()=>{
  const username = qs('regUsername').value.trim();
  const password = qs('regPassword').value;
  const res = await postJSON('/api/register', {username, password});
  qs('regStatus').textContent = res.ok ? 'Registered' : (res.json?.error || 'Error');
});

qs('loginBtn').addEventListener('click', async ()=>{
  const username = qs('loginUsername').value.trim();
  const password = qs('loginPassword').value;
  const res = await postJSON('/api/login', {username, password});
  if (res.ok && res.json?.token){
    localStorage.setItem('authToken', res.json.token);
    qs('loginStatus').textContent = 'Logged in — token saved to localStorage';
  } else {
    qs('loginStatus').textContent = res.json?.error || 'Login failed';
  }
});

qs('callProtected').addEventListener('click', async ()=>{
  const token = localStorage.getItem('authToken');
  const res = await fetch('/api/protected', { headers: { Authorization: token ? `Bearer ${token}` : '' } });
  const text = await res.json().catch(()=> ({}));
  qs('protectedResult').textContent = res.ok ? (text.message || 'ok') : (text.error || 'Not authorized');
});
