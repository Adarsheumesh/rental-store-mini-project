/**
 * Auto-Return System for Tool Rental Store
 * 
 * This script implements an automatic return system with penalty for past due rentals.
 * When a rental item is past its due date, the system will automatically initiate a return
 * and apply a penalty of ₹50 to the user's wallet.
 */

$(document).ready(function() {
    // View return details handler
    $('.view-return-details').on('click', function() {
        const orderId = $(this).data('order-id');
        const productId = $(this).data('product-id');
        
        // Show the modal
        const returnModal = new bootstrap.Modal(document.getElementById('returnDetailsModal'));
        
        // Get return details from the server
        $.ajax({
            url: `/return-details/${orderId}/${productId}`,
            method: 'GET',
            success: function(response) {
                if (response.success) {
                    const item = response.item;
                    
                    // Populate basic return info
                    $('#returnModalProductName').text(item.product_name || 'Unknown Product');
                    $('#returnModalOrderId').text(orderId);
                    
                    // Set return status with appropriate badge
                    const statusBadge = $('#returnModalStatus');
                    statusBadge.text(item.status || 'Returned');
                    
                    if (item.status === 'auto_returned' || item.status === 'return_initiated') {
                        statusBadge.removeClass().addClass('badge bg-warning');
                        // Show penalty info for auto-returned items
                        $('#penaltyInfo').show();
                        $('#penaltyAmount').text('50');
                        // Show auto-return event in timeline
                        $('#autoReturnEvent').show();
                        $('#returnTimelineAutoReturnDate').text(item.return_initiated_at || 'N/A');
                    } else {
                        statusBadge.removeClass().addClass('badge bg-success');
                        $('#penaltyInfo').hide();
                        $('#autoReturnEvent').hide();
                    }
                    
                    // Set dates
                    $('#returnModalReturnDate').text(item.return_completed_at || 'N/A');
                    $('#returnTimelineOrderDate').text(item.order_date || 'N/A');
                    $('#returnTimelineDeliveryDate').text(item.delivery_date || 'N/A');
                    $('#returnTimelineDueDate').text(item.rent_to || 'N/A');
                    $('#returnTimelineReturnDate').text(item.return_completed_at || 'N/A');
                    
                    // Show the modal
                    returnModal.show();
                } else {
                    // Show error toast
                    showToast('Error', response.message || 'Failed to load return details', true);
                }
            },
            error: function(xhr, status, error) {
                showToast('Error', 'Failed to load return details. Please try again.', true);
                console.error('Error loading return details:', error);
            }
        });
    });
    
    // Override the global confirm function when in Late Returns tab (if not already done)
    if (!window.confirmOverridden) {
        const originalConfirm = window.confirm;
        window.confirm = function(message) {
            // If we're switching tabs or the message contains penalty text, auto-confirm
            if (window.isTabSwitching || (message && message.includes("penalty"))) {
                console.log("Suppressing confirmation dialog during tab switching");
                return true; // Auto-confirm
            }
            // Otherwise use original confirm
            return originalConfirm.apply(this, arguments);
        };
        window.confirmOverridden = true;
        
        // Add event handlers for tab buttons if not already added
        if (!window.tabHandlersAdded) {
            $('#normal-returns-tab, #auto-returns-tab').on('click', function() {
                // Set flag to prevent checkPastDueRentals from processing
                window.isTabSwitching = true;
                console.log("Tab switching detected in auto-return.js");
                
                // Reset flag after tab switch is complete
                setTimeout(function() {
                    window.isTabSwitching = false;
                }, 800);  // Increased timeout to ensure complete tab switching
            });
            window.tabHandlersAdded = true;
        }
    }
    
    // Function to check for past due rentals
    function checkPastDueRentals() {
        // Skip processing if we're just switching tabs
        if (window.isTabSwitching) {
            console.log('Skipping checkPastDueRentals during tab switch');
            return;
        }
        
        console.log('Checking for past due rentals...');
        const today = new Date();
        today.setHours(0, 0, 0, 0); // Reset time to start of day
        
        // Look for all active rental items 
        $('.badge.bg-primary, .badge:contains("Active")').each(function() {
            console.log('Found active rental item');
            const statusBadge = $(this);
            const itemRow = statusBadge.closest('tr, .order-item');
            
            // Try different ways to extract the return date
            let rentToText = '';
            let returnDateStr = '';
            
            // Method 1: Look for rental period text in the DOM
            const rentalPeriodText = itemRow.find('small:contains("Rental Period")').text();
            if (rentalPeriodText) {
                console.log('Found rental period text:', rentalPeriodText);
                const rentToMatch = rentalPeriodText.match(/to\s+(\d{4}-\d{2}-\d{2})/);
                if (rentToMatch && rentToMatch[1]) {
                    returnDateStr = rentToMatch[1];
                }
            }
            
            // Method 2: Look for directly displayed rental period
            if (!returnDateStr) {
                const rentalPeriodElement = itemRow.find(':contains("Rental Period:")').last();
                if (rentalPeriodElement.length) {
                    const rentalText = rentalPeriodElement.text();
                    console.log('Found rental period element:', rentalText);
                    const dateMatch = rentalText.match(/to\s+(\d{4}-\d{2}-\d{2})/);
                    if (dateMatch && dateMatch[1]) {
                        returnDateStr = dateMatch[1];
                    }
                }
            }
            
            // If we still don't have a date, try getting it from the DOM structure
            if (!returnDateStr) {
                console.log('Trying to find date from DOM structure');
                // Try to find a date that looks like YYYY-MM-DD or DD-MM-YYYY
                const dateText = itemRow.text();
                const dateMatch = dateText.match(/(\d{4}-\d{2}-\d{2})/g);
                if (dateMatch && dateMatch.length >= 2) {
                    // Assume the second date is the end date
                    returnDateStr = dateMatch[1]; 
                    console.log('Found date match:', returnDateStr);
                }
            }
            
            // If we still don't have a return date, try one last method
            if (!returnDateStr) {
                // Look for any text containing a date pattern
                const allText = itemRow.text();
                console.log('Searching in all text:', allText);
                const anyDateMatch = allText.match(/(\d{4}-\d{2}-\d{2}|\d{2}\/\d{2}\/\d{4})/g);
                if (anyDateMatch && anyDateMatch.length >= 2) {
                    const potentialEndDate = anyDateMatch[anyDateMatch.length - 1];
                    console.log('Found potential end date:', potentialEndDate);
                    returnDateStr = potentialEndDate;
                }
            }
            
            console.log('Return date string found:', returnDateStr);
            
            if (!returnDateStr) {
                console.log('Could not find return date for item');
                return;
            }
            
            // Parse the return date, handling different formats
            let returnDate;
            if (returnDateStr.includes('/')) {
                // Handle DD/MM/YYYY format
                const [day, month, year] = returnDateStr.split('/');
                returnDate = new Date(year, month - 1, day);
            } else {
                // Handle YYYY-MM-DD format
                returnDate = new Date(returnDateStr);
            }
            
            returnDate.setHours(23, 59, 59, 999); // End of day
            console.log('Return date:', returnDate, 'Today:', today);
            
            // Check if return date has passed
            if (returnDate < today) {
                console.log('Found past due rental!', returnDate);
                
                // Get item information
                // Try multiple ways to get the order ID and product ID
                let orderId = '';
                let productId = '';
                
                // Method 1: Try data attributes on buttons
                const actionButton = itemRow.find('button[data-order-id], a[data-order-id]');
                if (actionButton.length) {
                    orderId = actionButton.data('order-id');
                    productId = actionButton.data('product-id');
                }
                
                // Method 2: Try to find the order ID in the details
                if (!orderId) {
                    const orderIdText = $('*:contains("Order ID:")').text();
                    const orderIdMatch = orderIdText.match(/Order ID:?\s*([\w-]+)/);
                    if (orderIdMatch && orderIdMatch[1]) {
                        orderId = orderIdMatch[1];
                    }
                }
                
                // Method 3: Look for hidden inputs
                if (!orderId) {
                    const orderIdInput = itemRow.find('input[name="order_id"]');
                    if (orderIdInput.length) {
                        orderId = orderIdInput.val();
                    }
                }
                
                // Try to get the product ID if we still don't have it
                if (!productId && orderId) {
                    const productName = itemRow.find('h4, h5, strong').first().text().trim();
                    console.log('Product name:', productName);
                    
                    // Use the first return or view details button we can find
                    const returnButton = itemRow.find('.btn:contains("Return")');
                    if (returnButton.length) {
                        console.log('Found return button, extracting URL or onclick handler');
                        const onClickAttr = returnButton.attr('onclick');
                        if (onClickAttr) {
                            const productIdMatch = onClickAttr.match(/['"]([\w-]+)['"]/);
                            if (productIdMatch && productIdMatch[1]) {
                                productId = productIdMatch[1];
                            }
                        }
                        
                        // If button has a data attribute for product
                        if (!productId) {
                            productId = returnButton.data('product') || returnButton.data('product-id');
                        }
                    }
                    
                    // If we still don't have the product ID, try to find it elsewhere
                    if (!productId) {
                        // Assume it's included in a query parameter or element on the page
                        const viewDetailsLink = itemRow.find('a:contains("View Details")');
                        if (viewDetailsLink.length) {
                            const href = viewDetailsLink.attr('href');
                            if (href) {
                                const productIdMatch = href.match(/product[_-]id=([\w-]+)/);
                                if (productIdMatch && productIdMatch[1]) {
                                    productId = productIdMatch[1];
                                }
                            }
                        }
                    }
                }
                
                // Get the product name
                const productName = itemRow.find('h4, h5, strong').first().text().trim();
                
                console.log('Order ID:', orderId, 'Product ID:', productId, 'Product name:', productName);
                
                // Only proceed if we have all required information
                if (orderId && (productId || productName)) {
                    // Initiate auto-return with penalty
                    console.log('Initiating auto-return for', orderId, productId || productName);
                    initiateAutoReturn(orderId, productId || '-', productName || 'Unknown Product');
                }
            }
        });
    }
    
    // Function to handle auto-return
    function initiateAutoReturn(orderId, productId, productName) {
        console.log('Initiating auto-return for', orderId, productId, productName);
        
        // First try to get user_id from the meta tag or hidden input
        let userId = $('meta[name="user-id"]').attr('content') || $('#user-id').val();
        
        // If still no user ID, try to get it from the URL or another source
        if (!userId) {
            console.log('User ID not found in meta or hidden input, trying other methods');
            
            // Try to get from URL if it contains user_id parameter
            const urlParams = new URLSearchParams(window.location.search);
            userId = urlParams.get('user_id');
            
            // If still no user ID, look for it in the page content
            if (!userId) {
                const userIdMatch = document.body.innerHTML.match(/user[_-]id['":\s]*(['"a-zA-Z0-9_-]+)['"]/i);
                if (userIdMatch && userIdMatch[1]) {
                    userId = userIdMatch[1].replace(/['"]/g, '');
                }
            }
        }
        
        if (!userId) {
            console.error('Could not determine user ID for auto-return');
            showToast('Error', 'Unable to process auto-return: User ID not found', true);
            return;
        }
        
        console.log('Using user ID:', userId);
        
        // Show "Processing" toast
        showToast('Processing', `Processing auto-return for overdue item "${productName}"...`, false);
        
        $.ajax({
            url: '/auto-return',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                order_id: orderId,
                product_id: productId,
                user_id: userId
            }),
            success: function(response) {
                if (response.success) {
                    console.log('Auto-return successful:', response);
                    
                    // Update UI to show returned status
                    const statusCell = $(`tr[data-order-id="${orderId}"][data-product-id="${productId}"] .status-cell, 
                                         tr:contains("${orderId}") .status-cell,
                                         div:contains("${orderId}") .badge.bg-primary`).first();
                    
                    if (statusCell.length) {
                        statusCell.removeClass('bg-primary').addClass('bg-warning').text('Return Initiated');
                        statusCell.after(`<br><small class="text-danger">Penalty Applied: ₹${response.penalty_amount}</small>`);
                    } else {
                        // Try to find the status badge
                        const statusBadge = $(`.badge:contains("Active")`).filter(function() {
                            return $(this).closest('tr, div').text().includes(orderId);
                        });
                        
                        if (statusBadge.length) {
                            statusBadge.removeClass('bg-primary').addClass('bg-warning').text('Return Initiated');
                            statusBadge.after(`<br><small class="text-danger">Penalty Applied: ₹${response.penalty_amount}</small>`);
                        }
                    }
                    
                    // Show success notification
                    showToast('Auto-Return Initiated', `The return process has been initiated for "${productName}" due to overdue rental. A penalty of ₹${response.penalty_amount} has been applied to your wallet.`, false);
                    
                    // Update wallet balance if provided
                    if (response.new_wallet_balance !== undefined) {
                        // Update wallet balance display if it exists
                        $('#walletBalance, #wallet-balance, .wallet-balance').text(`₹${parseFloat(response.new_wallet_balance).toFixed(2)}`);
                    }
                    
                    // Update wallet deposit if provided
                    if (response.new_wallet_deposit !== undefined) {
                        // Update wallet deposit display if it exists
                        $(`.wallet-deposit-amount[data-order-id="${orderId}"]`).text(`₹${parseFloat(response.new_wallet_deposit).toFixed(2)}`);
                        
                        // Add autoreturn charge to order items if not already displayed
                        const orderItemsContainer = $(`.order-items-container[data-order-id="${orderId}"]`);
                        if (orderItemsContainer.length && !orderItemsContainer.find('.autoreturn-charge').length) {
                            orderItemsContainer.append(`
                                <div class="autoreturn-charge row border-top pt-2 mt-2">
                                    <div class="col-md-8">
                                        <strong class="text-danger">Auto-Return Charge</strong>
                                    </div>
                                    <div class="col-md-4 text-end">
                                        <span class="text-danger">₹50.00</span>
                                    </div>
                                </div>
                            `);
                        }
                    }
                    
                    // Refresh the page after a delay
                    setTimeout(() => {
                        location.reload();
                    }, 5000);
                } else {
                    console.error('Auto-return failed:', response.error);
                    showToast('Error', response.error || 'Failed to process auto-return', true);
                }
            },
            error: function(xhr, status, error) {
                console.error('Auto-return error:', error, xhr.responseText);
                showToast('Error', 'Failed to process auto-return. Please try again.', true);
            }
        });
    }
    
    // Run the check when page loads
    checkPastDueRentals();
    
    // Also run the check periodically (every hour)
    setInterval(checkPastDueRentals, 3600000);
});

// Helper function for showing toast notifications
function showToast(title, message, isError = false) {
    // Check if we have a toast container
    let toastContainer = $('.toast-container');
    if (!toastContainer.length) {
        toastContainer = $('<div class="toast-container position-fixed bottom-0 end-0 p-3"></div>');
        $('body').append(toastContainer);
    }
    
    // Create toast element
    const toastId = 'toast-' + Date.now();
    const toastHTML = `
        <div id="${toastId}" class="toast align-items-center ${isError ? 'text-bg-danger' : 'text-bg-primary'}" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="d-flex">
                <div class="toast-body">
                    <strong>${title}</strong>: ${message}
                </div>
                <button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        </div>
    `;
    
    // Add toast to container
    toastContainer.append(toastHTML);
    
    // Initialize and show the toast
    const toastElement = new bootstrap.Toast(document.getElementById(toastId), {
        autohide: true,
        delay: 5000
    });
    toastElement.show();
}
