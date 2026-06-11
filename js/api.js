const API_BASE = 'https://gowork-backend-jb8p.onrender.com/api';

function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
        'Content-Type': 'application/json',
        'Authorization': token ? `Bearer ${token}` : ''
    };
}

async function registerUser(username, email, password, role) {
    const res = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password, role })
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
        localStorage.setItem('token',    data.token);
        localStorage.setItem('role',     data.role);
        localStorage.setItem('username', data.username);
        localStorage.setItem('email',    data.email || '');
    }
    return data;
}

async function forgotPassword(email) {
    const res = await fetch(`${API_BASE}/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
    });
    return res.json();
}

async function resetPassword(token, newPassword) {
    const res = await fetch(`${API_BASE}/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, newPassword })
    });
    return res.json();
}

async function getWorkers(skill = '', maxRate = '') {
    let url = `${API_BASE}/workers?`;
    if (skill)   url += `skill=${encodeURIComponent(skill)}&`;
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

async function deleteAccountPermanently() {
    const res = await fetch(`${API_BASE}/auth/delete-account`, {
        method: 'DELETE',
        headers: getAuthHeaders()
    });
    return res.json();
}
