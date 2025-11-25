document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const errorMessage = document.getElementById('errorMessage');

    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.classList.add('show');
        setTimeout(() => {
            errorMessage.classList.remove('show');
        }, 5000);
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();

            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json();

                if (response.ok) {
                    localStorage.setItem('authToken', data.token);
                    // Redirect admin users to admin dashboard
                    if (data.isAdmin) {
                        window.location.href = '/admin-dashboard.html';
                    } else {
                        window.location.href = '/dashboard.html';
                    }
                } else {
                    showError(data.error || 'Login failed. Please try again.');
                }
            } catch (error) {
                console.error('Login error:', error);
                showError('An error occurred. Please try again.');
            }
        });
    }

    if (signupForm) {
        signupForm.addEventListener('submit', async function(e) {
            e.preventDefault();

            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            if (password.length < 6) {
                showError('Password must be at least 6 characters long');
                return;
            }

            try {
                const response = await fetch('/api/signup', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ name, email, password })
                });

                const data = await response.json();

                if (response.ok) {
                    localStorage.setItem('authToken', data.token);
                    // Redirect admin users to admin dashboard
                    if (data.isAdmin) {
                        window.location.href = '/admin-dashboard.html';
                    } else {
                        window.location.href = '/dashboard.html';
                    }
                } else {
                    showError(data.error || 'Signup failed. Please try again.');
                }
            } catch (error) {
                console.error('Signup error:', error);
                showError('An error occurred. Please try again.');
            }
        });
    }
});
