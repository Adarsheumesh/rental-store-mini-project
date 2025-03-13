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
                
                // Get the order and first item
                const order = response.order;
                const item = order.items[0];
                
                // Check if order is cancelled
                const isCancelled = item.status.toLowerCase() === 'cancelled' || 
                                   item.status.toLowerCase() === 'partially_cancelled';
                
                // Check if order can be cancelled (ordered status and within 10 minutes)
                const isOrdered = item.status.toLowerCase() === 'ordered';
                const orderTime = new Date(order.created_at);
                const currentTime = new Date();
                const timeDiffMinutes = (currentTime - orderTime) / (1000 * 60);
                const canCancel = isOrdered && timeDiffMinutes <= 10;
                
                let html = '';
                
                if (isCancelled) {
                    // Special display for cancelled orders
                    html = `
                        <div class="p-3">
                            <h4>Order Details</h4>
                            
                            <div class="order-cancelled mb-4 text-center">
                                <div class="cancelled-icon mb-3">
                                    <i class="fa fa-times-circle fa-4x text-danger"></i>
                                </div>
                                <h5 class="mb-3">Order ${item.status.toLowerCase() === 'partially_cancelled' ? 'Partially ' : ''}Cancelled</h5>
                                <p class="text-muted">
                                    ${item.status.toLowerCase() === 'partially_cancelled' 
                                        ? `Cancelled Quantity: ${item.cancelled_quantity || 'N/A'}, Remaining: ${item.quantity || 'N/A'}`
                                        : `This order was cancelled on ${item.cancelled_at ? new Date(item.cancelled_at).toLocaleString() : 'N/A'}`
                                    }
                                </p>
                                ${item.cancellation_reason ? `<p><strong>Reason:</strong> ${item.cancellation_reason}</p>` : ''}
                            </div>
                        </div>
                    `;
                } else {
                    // Create progress bar based on status for non-cancelled orders
                    const statuses = ['ordered', 'in_transit', 'out_for_delivery', 'delivered', 'return_initiated', 'returned'];
                    const currentStatusIndex = statuses.indexOf(item.status.toLowerCase());
                    
                    html = `
                        <div class="p-3">
                            <h4>Order Details</h4>
                            
                            <div class="order-progress mb-4">
                                <h5 class="mb-3">Order Progress</h5>
                                <div class="progress-track">
                                    <div class="progress-steps">
                                        <div class="step ${currentStatusIndex >= 0 ? 'completed' : ''}">
                                            <div class="step-icon">
                                                <i class="fa fa-shopping-cart"></i>
                                            </div>
                                            <p class="step-text">Ordered</p>
                                            <small class="step-date">${order.created_at ? new Date(order.created_at).toLocaleString() : ''}</small>
                                        </div>
                                        <div class="step ${currentStatusIndex >= 1 ? 'completed' : ''}">
                                            <div class="step-icon">
                                                <i class="fa fa-truck"></i>
                                            </div>
                                            <p class="step-text">In Transit</p>
                                            <small class="step-date">${item.in_transit_at ? new Date(item.in_transit_at).toLocaleString() : ''}</small>
                                        </div>
                                        <div class="step ${currentStatusIndex >= 2 ? 'completed' : ''}">
                                            <div class="step-icon">
                                                <i class="fa fa-shipping-fast"></i>
                                            </div>
                                            <p class="step-text">Out for Delivery</p>
                                            <small class="step-date">${item.out_for_delivery_at ? new Date(item.out_for_delivery_at).toLocaleString() : ''}</small>
                                        </div>
                                        <div class="step ${currentStatusIndex >= 3 ? 'completed' : ''}">
                                            <div class="step-icon">
                                                <i class="fa fa-box"></i>
                                            </div>
                                            <p class="step-text">Delivered</p>
                                            <small class="step-date">${item.delivered_at ? new Date(item.delivered_at).toLocaleString() : ''}</small>
                                        </div>
                                        <div class="step ${currentStatusIndex >= 4 ? 'completed' : ''}">
                                            <div class="step-icon">
                                                <i class="fa fa-undo"></i>
                                            </div>
                                            <p class="step-text">Return Initiated</p>
                                            <small class="step-date">${item.return_initiated_at ? new Date(item.return_initiated_at).toLocaleString() : ''}</small>
                                        </div>
                                        <div class="step ${currentStatusIndex >= 5 ? 'completed' : ''}">
                                            <div class="step-icon">
                                                <i class="fa fa-check-circle"></i>
                                            </div>
                                            <p class="step-text">Returned</p>
                                            <small class="step-date">${item.return_completed_at ? new Date(item.return_completed_at).toLocaleString() : ''}</small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                }
                
                // Add common order information section for all order types
                html += `
                    <div class="order-info mt-4">
                        <div class="row">
                            <div class="col-md-6">
                                <h5>Order Details</h5>
                                <p><strong>Order ID:</strong> ${order.order_id}</p>
                                <p><strong>Order Date:</strong> ${new Date(order.created_at).toLocaleString()}</p>
                                <p><strong>Product:</strong> ${item.product_name}</p>
                                <p><strong>Total Amount:</strong> ₹${order.order_total.toFixed(2)}</p>
                                <p><strong>Store:</strong> ${item.store_name || 'Rentedd'}</p>
                            </div>
                            <div class="col-md-6">
                                <h5>Delivery Details</h5>
                                <p><strong>Shipping Address:</strong> ${order.shipping_address || 'Not available'}</p>
                                <p><strong>Payment ID:</strong> ${order.payment_id || 'Not available'}</p>
                                <p><strong>Status:</strong> <span class="badge ${isCancelled ? 'bg-danger' : 'bg-primary'}">${item.status}</span></p>
                                <p><strong>Quantity:</strong> ${item.quantity}</p>
                                <p><strong>Rental Period:</strong> ${item.rent_from} to ${item.rent_to}</p>
                            </div>
                        </div>
                    </div>
                `;
                
                // Add cancel button if order can be cancelled
                if (canCancel) {
                    html += `
                        <div class="mt-4 text-center">
                            <p class="text-muted small">You can cancel this order within 10 minutes of placing it.</p>
                            <button class="btn btn-danger cancel-order-btn" 
                                    data-order-id="${order.order_id}" 
                                    data-product-id="${item.product_id || ''}"
                                    data-product-name="${item.product_name || ''}">
                                <i class="fa fa-times"></i> Cancel Order
                            </button>
                        </div>
                    `;
                } else if (isOrdered) {
                    html += `
                        <div class="mt-4 text-center">
                            <p class="text-muted small">Orders can only be cancelled within 10 minutes of placing them.</p>
                        </div>
                    `;
                }
                
                $('#moreDetailsContent').html(html);
                
                // Add click handler for the cancel button in the modal
                $('.cancel-order-btn').on('click', function() {
                    const orderId = $(this).data('order-id');
                    const productId = $(this).data('product-id');
                    const productName = $(this).data('product-name');
                    
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