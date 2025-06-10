// login.js flask frontend in js
async function loginUser(email, password) {
    const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
    });

    if (response.ok) {
        const data = await response.json();
        // Store JWT securely (example: localStorage, but HttpOnly cookies are safer)
        localStorage.setItem('access_token', data.access_token);
        // Redirect or update UI
        window.location.href = '/dashboard.html';
    } else {
        const error = await response.json();
        alert(error.msg);
    }
}

// Example usage with a form
document.getElementById('login-form').addEventListener('submit', function(e) {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    loginUser(email, password);
});
