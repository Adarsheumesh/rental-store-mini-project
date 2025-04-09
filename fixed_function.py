@app.route('/lost-products')
def lost_products():
    # Check if user is logged in
    if 'user_info' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    user_info = session['user_info']
    store_name = user_info.get('store_name')
    
    try:
        # Get all orders
        orders = db.child("orders").get().val() or {}
        
        # List to store lost product data
        lost_products = []
        
        # Process orders to find lost items
        for order_id, order in orders.items():
            # Skip orders from other stores
            if order.get('store_name') != store_name:
                continue
                
            # Check order items for lost status
            if 'items' in order and isinstance(order['items'], list):
                for item in order['items']:
                    if item.get('status') == 'lost':
                        # Get the product details
                        product_id = item.get('product_id')
                        if not product_id:
                            continue
                            
                        product = db.child("products").child(product_id).get().val()
                        
                        if product:
                            # Create a combined object with product and order details
                            lost_product = product.copy()
                            lost_product['product_id'] = product_id
                            lost_product['status'] = 'lost'
                            lost_product['reported_date'] = item.get('return_completed_at', '').split('T')[0] if item.get('return_completed_at') else ''
                            lost_product['order_id'] = order_id
                            lost_product['rental_days'] = item.get('rental_days')
                            lost_product['rent_from'] = item.get('rent_from')
                            lost_product['rent_to'] = item.get('rent_to')
                            lost_product['last_location'] = order.get('shipping_address', '')
                            
                            lost_products.append(lost_product)
            
            # Also check for individual items in the order that might be marked as lost
            for key, value in order.items():
                if key.startswith('item_') and isinstance(value, dict) and value.get('status') == 'lost':
                    product_id = value.get('product_id')
                    if not product_id:
                        continue
                        
                    product = db.child("products").child(product_id).get().val()
                    
                    if product:
                        lost_product = product.copy()
                        lost_product['product_id'] = product_id
                        lost_product['status'] = 'lost'
                        lost_product['reported_date'] = value.get('return_completed_at', '').split('T')[0] if value.get('return_completed_at') else ''
                        lost_product['order_id'] = order_id
                        lost_product['rental_days'] = value.get('rental_days')
                        lost_product['rent_from'] = value.get('rent_from')
                        lost_product['rent_to'] = value.get('rent_to')
                        lost_product['last_location'] = order.get('shipping_address', '')
                        
                        lost_products.append(lost_product)
        
        if not lost_products:
            flash('No lost products found.', 'info')
            
    except Exception as e:
        flash(f"Failed to fetch lost products: {str(e)}", 'danger')
        return redirect(url_for('index'))

    # Render the lost products template with the fetched data
    return render_template('andshop/lost-products.html', products=lost_products, user=user_info) 