/**
 * Cart utility functions for ToolHive
 */

// Update cart count function - for real-time cart count updates
function updateCartCount(count) {
    const cartCounters = document.querySelectorAll('.cart-counter');
    cartCounters.forEach(counter => {
        counter.textContent = count;
        counter.dataset.cartCount = count;
    });
}

// Show popup message
function showCartPopup(message, isError = false) {
    console.log('Showing popup with message:', message);
    var popup = document.getElementById('custom-popup');
    var popupMessage = document.getElementById('popup-message');
    
    if (popup && popupMessage) {
        popupMessage.textContent = message;
        
        // Add or remove error class based on isError parameter
        if (isError) {
            popup.classList.add('error');
        } else {
            popup.classList.remove('error');
        }
        
        popup.style.display = 'block';
        
        // Remove the popup after 3 seconds
        setTimeout(function() {
            popup.style.display = 'none';
        }, 3000);
    } else {
        console.error('Popup elements not found');
        // Fallback to alert if custom popup isn't available
        alert(message);
    }
}

// Initialize cart-related event listeners
function initCartEvents() {
    // Since individual pages now handle their own cart events with debouncing,
    // this function is primarily for pages that don't have specific cart handling
    
    // We'll only add listeners to elements that don't already have cart handlers
    document.querySelectorAll('.add-cart:not([data-has-cart-event])').forEach(button => {
        // Mark the button as having our event handler
        button.dataset.hasCartEvent = 'true';
        
        button.addEventListener('click', function(e) {
            // Stop propagation to prevent duplicate handling
            e.stopPropagation();
            
            // Check if already handled
            if (e.handled === true) return;
            e.handled = true;
            
            if (this.classList.contains('disabled')) return;
            
            e.preventDefault();
            const productId = this.dataset.productId;
            const quantity = document.getElementById('quantity') ? 
                parseInt(document.getElementById('quantity').value) || 1 : 1;
            
            // Call add to cart AJAX function
            addToCart(productId, quantity);
        });
    });
}

// Add to cart AJAX function
function addToCart(productId, quantity = 1) {
    // Debounce the request
    if (window._lastCartRequest && 
        window._lastCartRequest.id === productId && 
        Date.now() - window._lastCartRequest.time < 1000) {
        console.log('Ignoring duplicate cart request (global handler)');
        return;
    }
    
    // Set request tracking
    window._lastCartRequest = {
        id: productId,
        time: Date.now()
    };
    
    // Check if quantity exceeds maximum allowed
    if (quantity > 5) {
        showCartPopup('Maximum 5 quantities per product allowed', true);
        if (document.getElementById('quantity')) {
            document.getElementById('quantity').value = 5; // Reset to maximum
        }
        return;
    }
    
    // Log the request for debugging
    console.log('Adding to cart (global handler):', { productId, quantity });
    
    fetch('/add-to-cart', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            product_id: productId,
            quantity: quantity
        })
    })
    .then(response => response.json())
    .then(data => {
        console.log('Cart response:', data);
        if (data.success) {
            showCartPopup(data.message);
            
            if (data.cart_count !== undefined) {
                updateCartCount(data.cart_count);
            }
        } else {
            // Special case for products already in cart
            if (data.already_in_cart) {
                showCartPopup('Product is already in your cart', true);
            } else {
                showCartPopup(data.message, true);
            }
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showCartPopup('An error occurred. Please try again.', true);
    });
}

// Initialize on DOM content loaded
document.addEventListener('DOMContentLoaded', function() {
    // Add a flag to window to prevent multiple initializations
    if (!window._cartEventsInitialized) {
        window._cartEventsInitialized = true;
        
        // Wait a short time to let individual page handlers initialize first
        setTimeout(function() {
            initCartEvents();
            console.log('Cart global events initialized');
        }, 100);
    }
}); 