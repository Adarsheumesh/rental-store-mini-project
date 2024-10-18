$(document).ready(function() {
    // Logout function
    function logout() {
        $.ajax({
            url: '/logout',
            type: 'GET',
            success: function(response) {
                // Clear any client-side storage
                localStorage.clear();
                sessionStorage.clear();

                // Redirect to login page
                window.location.href = '/login';
            },
            error: function(xhr, status, error) {
                console.error("Logout error:", error);
                alert("An error occurred during logout. Please try again.");
            }
        });
    }

    // Attach logout function to logout link
    $('.logout-link').on('click', function(e) {
        e.preventDefault();
        logout();
    });

    // Check authentication status
    function checkAuth() {
        $.ajax({
            url: '/check_auth',
            type: 'GET',
            success: function(response) {
                if (!response.authenticated) {
                    window.location.href = '/login';
                }
            },
            error: function(xhr, status, error) {
                console.error("Auth check error:", error);
                window.location.href = '/login';
            }
        });
    }

    // Run auth check on page load
    checkAuth();

    // Disable back button
    history.pushState(null, null, location.href);
    window.onpopstate = function () {
        history.go(1);
    };
});