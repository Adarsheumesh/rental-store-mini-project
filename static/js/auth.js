(function() {
    // Check if user is logged in
    function checkAuth() {
        fetch('/check_auth', {
            method: 'GET',
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Not authenticated');
            }
            return response.json();
        })
        .then(data => {
            if (!data.authenticated) {
                window.location.href = '/login';
            }
        })
        .catch(() => {
            window.location.href = '/login';
        });
    }

    // Perform logout
    function logout(event) {
        if (event) {
            event.preventDefault();
        }
        fetch('/logout', {
            method: 'GET',
            credentials: 'same-origin'
        })
        .then(() => {
            localStorage.clear();
            sessionStorage.clear();
            window.location.href = '/login';
        })
        .catch(error => {
            console.error('Logout error:', error);
            alert('An error occurred during logout. Please try again.');
        });
    }

    // Attach event listeners
    document.addEventListener('DOMContentLoaded', function() {
        const logoutLinks = document.querySelectorAll('.logout-link');
        logoutLinks.forEach(link => {
            link.addEventListener('click', logout);
        });

        // Only run checkAuth on protected pages
        if (document.body.classList.contains('protected-page')) {
            checkAuth();

            // Disable back/forward cache for protected pages
            window.onpageshow = function(event) {
                if (event.persisted) {
                    checkAuth();
                }
            };

            // Disable back button for protected pages
            history.pushState(null, null, location.href);
            window.onpopstate = function() {
                history.go(1);
            };
        }
    });
})();
