// Change this line to use your real live Render domain link (e.g., https://gowork-backend-xxxx.onrender.com/api)
const API_BASE = 'https://gowork-backend.onrender.com/api';

function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
        'Content-Type': 'application/json',
        'Authorization': token ? `Bearer ${token}` : ''
    };
}

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
    if (data.token) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('role', data.role);
        localStorage.setItem('username', data.username);
    }
    return data;
}

async function getWorkers(skill = '', maxRate = '') {
    let url = `${API_BASE}/workers?`;
    if (skill) url += `skill=${encodeURIComponent(skill)}&`;
    if (maxRate) url += `maxRate=${maxRate}`;
    
    const res = await fetch(url);
    return res.json();
}

async function getMyProfile() {
    const res = await fetch(`${API_BASE}/workers/me`, {
        method: 'GET',
        headers: getAuthHeaders()
    });
    return res.json();
}

async function saveProfile(profileData) {
    const res = await fetch(`${API_BASE}/workers`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(profileData)
    });
    return res.json();
}
