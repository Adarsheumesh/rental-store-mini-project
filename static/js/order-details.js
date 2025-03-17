// Function to show order details
function showOrderDetails(orderId) {
    console.log('showOrderDetails called for order:', orderId);
    
    // Reset modal content
    $('#moreDetailsContent').empty().addClass('d-none');
    $('#orderDetailsLoading').removeClass('d-none');
    $('#orderDetailsError').addClass('d-none');
    
    // Show modal using jQuery
    $('#moreDetailsModal').modal('show');
    
    // Fetch order details
    $.ajax({
        url: '/get-order-details',
        method: 'GET',
        data: { order_id: orderId },
        success: function(response) {
            $('#orderDetailsLoading').addClass('d-none');
            
            if (response.success) {
                $('#moreDetailsContent').removeClass('d-none');
                
                // Get the order and its items
                const order = response.order;
                const items = order.items || [];
                
                let html = `<div class="p-3"><h4>Order Details</h4>`;
                
                // Order summary information
                html += `
                    <div class="order-summary mb-4">
                        <div class="row">
                            <div class="col-md-6">
                                <p><strong>Order ID:</strong> ${order.order_id || 'N/A'}</p>
                                <p><strong>Order Date:</strong> ${order.created_at ? new Date(order.created_at).toLocaleString() : 'N/A'}</p>
                                <p><strong>Total:</strong> ₹${parseFloat(order.subtotal || 0).toFixed(2)}</p>
                            </div>
                            <div class="col-md-6">
                                <p><strong>Shipping Address:</strong> ${order.shipping_address || 'N/A'}</p>
                            </div>
                        </div>
                    </div>
                `;
                
                // Items list with individual statuses
                html += `<h5 class="mb-3">Order Items</h5>`;
                
                html += `<div class="order-items mb-4">`;
                
                // Process each item separately with its own status
                items.forEach((item, index) => {
                    const isItemCancelled = item.status && item.status.toLowerCase() === 'cancelled';
                    const isItemPartialCancelled = item.status && item.status.toLowerCase() === 'partially_cancelled';
                    const isItemReturned = item.status && item.status.toLowerCase() === 'returned';
                    const isItemReturnInitiated = item.status && item.status.toLowerCase() === 'return_initiated';
                    
                    html += `
                        <div class="order-item p-3 mb-3 ${isItemCancelled ? 'bg-light' : ''}" style="border: 1px solid #eee; border-radius: 5px;">
                            <div class="row align-items-center">
                                <div class="col-md-2">
                                    <img src="${item.image_url || '/static/img/default-product.jpg'}" 
                                         alt="${item.product_name || 'Product'}" 
                                         class="img-fluid" style="max-width: 80px;">
                                </div>
                                <div class="col-md-4">
                                    <h6>${item.product_name || 'Unknown Product'}</h6>
                                    <p class="mb-0">Quantity: ${item.quantity || 1}</p>
                                    <p class="mb-0">Duration: ${item.rental_days || 1} days</p>
                                </div>
                                <div class="col-md-3">
                                    <p class="mb-1"><strong>Rental Period:</strong></p>
                                    <p class="mb-0">From: ${item.rent_from || 'N/A'}</p>
                                    <p class="mb-0">To: ${item.rent_to || 'N/A'}</p>
                                </div>
                                <div class="col-md-3 text-center">
                                    ${isItemCancelled ? 
                                        `<span class="badge bg-danger p-2">Cancelled</span>` : 
                                      isItemPartialCancelled ?
                                        `<span class="badge bg-warning text-dark p-2">Partially Cancelled</span><br>
                                         <small>Cancelled: ${item.cancelled_quantity || 'N/A'}, Remaining: ${item.quantity || 'N/A'}</small>` :
                                      isItemReturned ?
                                        `<span class="badge bg-success p-2">Returned</span>` :
                                      isItemReturnInitiated ?
                                        `<span class="badge bg-warning text-dark p-2">Return Initiated</span>` :
                                        `<span class="badge bg-primary p-2">${item.status || 'Active'}</span>`
                                    }
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                html += `</div>`; // End order-items
                
                // Check if any item can be cancelled (status is ordered and within 10 minutes)
                const orderTime = new Date(order.created_at);
                const currentTime = new Date();
                const timeDiffMinutes = (currentTime - orderTime) / (1000 * 60);
                const canCancel = timeDiffMinutes <= 10;
                
                // Add cancel buttons for individual items that can be cancelled
                if (canCancel) {
                    html += `<div class="mt-4 text-center">`;
                    
                    items.forEach((item, index) => {
                        if (item.status && (item.status.toLowerCase() === 'ordered' || item.status.toLowerCase() === 'partially_cancelled')) {
                            html += `
                                <button class="btn btn-outline-danger m-1 cancel-order-btn" 
                                        data-order-id="${order.order_id}" 
                                        data-product-id="${item.product_id || ''}"
                                        data-product-name="${item.product_name || ''}">
                                    <i class="fa fa-times"></i> Cancel ${item.status.toLowerCase() === 'partially_cancelled' ? 'Remaining' : ''} ${item.product_name || 'Item'}
                                </button>
                            `;
                        }
                    });
                    
                    html += `<p class="text-muted small mt-2">You can cancel items within 10 minutes of placing the order.</p>`;
                    html += `</div>`;
                } else {
                    html += `
                        <div class="mt-4 text-center">
                            <p class="text-muted small">Orders can only be cancelled within 10 minutes of placing them.</p>
                        </div>
                    `;
                }
                
                html += `</div>`; // End p-3 container
                
                $('#moreDetailsContent').html(html);
                
                // Add click handler for the cancel button in the modal
                $('.cancel-order-btn').on('click', function() {
                    const orderId = $(this).data('order-id');
                    const productId = $(this).data('product-id');
                    const productName = $(this).data('product-name');
                    
                    // Find the item and get its quantity
                    const item = items.find(i => i.product_id === productId);
                    
                    // If the item is partially cancelled, make sure we're using the remaining quantity
                    const quantity = item ? parseInt(item.quantity) || 1 : 1;
                    
                    // Populate the cancel item modal
                    $('#cancelItemOrderId').text(orderId);
                    $('#cancelItemProductName').text(productName);
                    
                    // Store product ID in a hidden field
                    if (!$('#cancelItemProductId').length) {
                        $('<input>').attr({
                            type: 'hidden',
                            id: 'cancelItemProductId',
                            value: productId
                        }).appendTo('#cancelItemModal .modal-body');
                    } else {
                        $('#cancelItemProductId').val(productId);
                    }
                    
                    // Populate quantity selector if quantity > 1
                    const $quantitySelector = $('#cancelQuantitySelector');
                    const $cancelQuantity = $('#cancelQuantity');
                    
                    $cancelQuantity.empty();
                    
                    if (quantity > 1) {
                        // Show quantity selector and populate options
                        $quantitySelector.show();
                        
                        for (let i = 1; i <= quantity; i++) {
                            $cancelQuantity.append(`<option value="${i}">${i}</option>`);
                        }
                    } else {
                        // Hide quantity selector for single items
                        $quantitySelector.hide();
                    }
                    
                    // Hide the details modal and show the cancel modal
                    const detailsModal = bootstrap.Modal.getInstance(document.getElementById('moreDetailsModal'));
                    detailsModal.hide();
                    
                    // Show the cancel modal using Bootstrap 5
                    setTimeout(() => {
                        const cancelModal = new bootstrap.Modal(document.getElementById('cancelItemModal'));
                        cancelModal.show();
                    }, 500);
                });
                
                // Make sure the CSS for the progress tracker is applied
                if (!$('#progress-tracker-css').length) {
                    $('head').append(`
                        <style id="progress-tracker-css">
                            .order-progress {
                                margin: 2rem 0;
                                position: relative;
                            }
                            
                            .progress-track {
                                margin: 30px 0;
                                position: relative;
                            }
                            
                            .progress-steps {
                                display: flex;
                                justify-content: space-between;
                                align-items: flex-start;
                                position: relative;
                            }
                            
                            .progress-steps::before {
                                content: '';
                                position: absolute;
                                top: 15px;
                                left: 0;
                                right: 0;
                                height: 2px;
                                background: #e0e0e0;
                                z-index: 1;
                            }
                            
                            .step {
                                position: relative;
                                z-index: 2;
                                text-align: center;
                                width: 16.66%;
                            }
                            
                            .step-icon {
                                width: 30px;
                                height: 30px;
                                background: #fff;
                                border: 2px solid #e0e0e0;
                                border-radius: 50%;
                                margin: 0 auto 10px;
                                display: flex;
                                align-items: center;
                                justify-content: center;
                            }
                            
                            .step.active .step-icon {
                                border-color: #007bff;
                                background: #007bff;
                                color: #fff;
                            }
                            
                            .step.completed .step-icon {
                                border-color: #28a745;
                                background: #28a745;
                                color: #fff;
                            }
                            
                            .step-text {
                                font-size: 12px;
                                margin: 5px 0;
                            }
                            
                            .step-date {
                                font-size: 11px;
                                color: #666;
                            }
                            
                            .order-cancelled {
                                padding: 2rem;
                                border: 1px solid #f8d7da;
                                border-radius: 8px;
                                background-color: #fff8f8;
                            }
                            
                            .cancelled-icon {
                                color: #dc3545;
                            }
                        </style>
                    `);
                }
            } else {
                $('#orderDetailsError').removeClass('d-none');
            }
        },
        error: function() {
            $('#orderDetailsLoading').addClass('d-none');
            $('#orderDetailsError').removeClass('d-none');
        }
    });
    
    // Prevent default action
    return false;
}

// Initialize when document is ready
$(document).ready(function() {
    console.log('Initializing order-details.js');
    
    // Remove any existing click handlers to prevent duplicates
    $('.view-order-details').off('click');
    
    // Add click handler for view details buttons
    $('.view-order-details').on('click', function(e) {
        e.preventDefault();
        const orderId = $(this).data('order-id');
        showOrderDetails(orderId);
    });
    
    // Add click handler for view return details buttons
    $('.view-return-details').off('click');
    $('.view-return-details').on('click', function(e) {
        e.preventDefault();
        const orderId = $(this).data('order-id');
        showOrderDetails(orderId);
    });
}); 