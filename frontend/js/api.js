const API_BASE = 'https://gowork-backend-jb8p.onrender.com/api';

async function registerUser(username, password, role) {
    const res = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, role })
    });
    return res.json();
}

async function loginUser(username, password) {
    const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (data.token) localStorage.setItem('token', data.token);
    return data;
}

async function getWorkers() {
    const res = await fetch(`${API_BASE}/workers`);
    return res.json();
}
