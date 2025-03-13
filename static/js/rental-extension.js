// Helper functions for rental extension
function calculatePerDayCharge(totalPrice, rentalDays) {
    return totalPrice / rentalDays;
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function addDays(dateString, days) {
    const date = new Date(dateString);
    date.setDate(date.getDate() + parseInt(days));
    return date.toISOString().split('T')[0];
}

function handleExtendRental(button) {
    console.log("handleExtendRental called");
    
    const orderId = button.getAttribute('data-order-id');
    const itemIndex = parseInt(button.getAttribute('data-item-index'));
    const item = JSON.parse(button.getAttribute('data-item'));
    const walletDeposit = parseFloat(button.getAttribute('data-wallet-deposit'));
    
    console.log("Button data:", orderId, itemIndex, item, walletDeposit);
    
    const perDayCharge = calculatePerDayCharge(item.total_price, item.rental_days);
    const maxPossibleDays = Math.floor(walletDeposit / perDayCharge);
    const maxDays = Math.min(3, maxPossibleDays);

    if (maxDays <= 0) {
        alert('Insufficient wallet deposit for extension');
        return;
    }

    // Set modal values
    document.getElementById('extendOrderId').value = orderId;
    document.getElementById('extendItemIndex').value = itemIndex;
    document.getElementById('currentRentTo').value = item.rent_to;
    document.getElementById('availableDeposit').value = `₹${walletDeposit}`;
    document.getElementById('perDayCharge').value = perDayCharge;
    document.getElementById('maxDays').value = item.rental_days;
    
    // Populate days dropdown
    const daysSelect = document.getElementById('extensionDays');
    daysSelect.innerHTML = '<option value="">Select days...</option>';
    for (let i = 1; i <= maxDays; i++) {
        daysSelect.innerHTML += `<option value="${i}">${i} day${i > 1 ? 's' : ''}</option>`;
    }

    // Add change event listener for days selection
    daysSelect.onchange = function() {
        const days = parseInt(this.value) || 0;
        const cost = days * perDayCharge;
        const remaining = walletDeposit - cost;
        document.getElementById('extensionCost').value = `₹${cost.toFixed(2)}`;
        document.getElementById('remainingDeposit').value = `₹${remaining.toFixed(2)}`;
    };

    // Show the modal
    const extendRentalModal = document.getElementById('extendRentalModal');
    const modal = new bootstrap.Modal(extendRentalModal);
    modal.show();
}

// Function to handle the extension submission
function submitExtension() {
    const orderId = document.getElementById('extendOrderId').value;
    const itemIndex = document.getElementById('extendItemIndex').value;
    const currentRentTo = document.getElementById('currentRentTo').value;
    const perDayCharge = parseFloat(document.getElementById('perDayCharge').value);
    const days = parseInt(document.getElementById('extensionDays').value);

    if (!days) {
        alert('Please select number of days to extend');
        return;
    }

    const extensionCost = days * perDayCharge;
    const newRentTo = addDays(currentRentTo, days);

    console.log("Submitting extension:", orderId, itemIndex, days, extensionCost, newRentTo);

    // Show loading state
    document.getElementById('extendRentalContent').classList.add('d-none');
    document.getElementById('extendRentalLoading').classList.remove('d-none');
    document.getElementById('extendRentalError').classList.add('d-none');

    // First get current wallet deposit - use the global database reference
    database.ref(`orders/${orderId}/wallet_deposit`).once('value')
        .then(snapshot => {
            const currentDeposit = snapshot.val();
            const newDeposit = currentDeposit - extensionCost;

            console.log("Current deposit:", currentDeposit, "New deposit:", newDeposit);

            // Prepare updates
            const updates = {
                [`orders/${orderId}/items/${itemIndex}/rent_to`]: newRentTo,
                [`orders/${orderId}/wallet_deposit`]: newDeposit,
                [`orders/${orderId}/items/${itemIndex}/rental_days`]: parseInt(document.getElementById('maxDays').value) + days
            };

            // Update Firebase - use the global database reference
            return database.ref().update(updates);
        })
        .then(() => {
            alert('Rental period extended successfully!');
            // Close the modal
            const extendRentalModal = document.getElementById('extendRentalModal');
            const modal = bootstrap.Modal.getInstance(extendRentalModal);
            if (modal) {
                modal.hide();
            } else {
                // Fallback for older Bootstrap versions
                $(extendRentalModal).modal('hide');
            }
            // Refresh the page
            location.reload();
        })
        .catch(error => {
            console.error('Error extending rental:', error);
            document.getElementById('extendRentalLoading').classList.add('d-none');
            document.getElementById('extendRentalError').classList.remove('d-none');
            document.getElementById('extendRentalError').textContent = 'Failed to extend rental. Please try again.';
            document.getElementById('extendRentalContent').classList.remove('d-none');
        });
}

// Initialize event listeners when document is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM loaded, initializing event listeners");
    
    // Add click event listener for submit extension button
    const submitBtn = document.getElementById('submitExtensionBtn');
    if (submitBtn) {
        submitBtn.addEventListener('click', submitExtension);
    }
}); 