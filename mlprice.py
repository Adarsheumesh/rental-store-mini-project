import pyrebase
import pandas as pd
import numpy as np
from statsmodels.tsa.arima.model import ARIMA
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import json
from flask import render_template

# Firebase configuration
config = {
     "apiKey": "AIzaSyB42nHmPcpj7BmOPPdO93lXqzA3PjjXZOc",
    "authDomain": "project-dbebd.firebaseapp.com",
    "projectId": "project-dbebd",
    "storageBucket": "project-dbebd.appspot.com",
    "messagingSenderId": "374516311348",
    "appId": "1:374516311348:web:d916facf6720a4e275f161",
    "databaseURL": "https://project-dbebd-default-rtdb.asia-southeast1.firebasedatabase.app/"
}

# Initialize Firebase app
firebase = pyrebase.initialize_app(config)
db = firebase.database()

def load_and_preprocess_data():
    # Fetch all orders from Firebase
    orders = db.child("orders").get().val()
    
    if not orders:
        print("No orders found in the database.")
        return pd.DataFrame()  # Return an empty DataFrame if no orders are found
    
    # Prepare data for time series analysis
    data = []
    for order_id, order in orders.items():
        order_date = order.get('created_at')  # Use 'created_at' instead of 'order_date'
        if order_date:
            try:
                date = pd.to_datetime(order_date).date()
                items = order.get('items', [])
                for item in items:
                    product_id = item.get('product_id', 'unknown_product')
                    data.append({
                        'date': date,
                        'product_id': product_id,
                        'rentals': 1  # Count each item as one rental
                    })
            except ValueError as e:
                print(f"Error processing order date for order {order_id}: {e}")
                print(f"Order data: {order}")
    
    if not data:
        print("No valid order data found.")
        return pd.DataFrame()  # Return an empty DataFrame if no valid data is found
    
    # Convert to DataFrame and aggregate by date and product_id
    df = pd.DataFrame(data)
    df['date'] = pd.to_datetime(df['date'])  # Ensure date is datetime
    df = df.groupby(['date', 'product_id'])['rentals'].sum().reset_index()
    
    return df

def simple_forecast(data, days_to_predict=7):
    # Ensure data index is a datetime object
    if not isinstance(data.index, pd.DatetimeIndex):
        data.index = pd.to_datetime(data.index)
    
    last_date = data.index[-1]

    # Generate future dates by adding 1 day to the last date
    future_dates = pd.date_range(start=last_date + timedelta(days=1), periods=days_to_predict)

    # Placeholder prediction logic
    predictions = [data['rentals'].iloc[-1]] * days_to_predict  # Replace with actual logic
    
    return data, pd.Series(predictions, index=future_dates)

def adjust_price(base_price, forecasted_demand, threshold=20):
    if forecasted_demand > threshold:
        return base_price * 1.2  # Increase price by 20%
    return base_price

def categorize_demand(demand):
    if demand > 20:
        return "High"
    elif demand > 10:
        return "Medium"
    else:
        return "Low"

def get_all_product_suggestions():
    data = load_and_preprocess_data()
    
    if data.empty:
        return []
    
    # Fetch all products
    products = db.child("products").get().val()
    
    suggestions = []
    
    for product_id, product_data in products.items():
        product_name = product_data.get('product_name', 'Unknown Product')
        base_price = float(product_data.get('product_price', 0))
        
        # Filter the data for the current product
        product_data = data[data['product_id'] == product_id].copy()
        if product_data.empty:
            print(f"No rental data available for product {product_name}")
            suggestions.append({
                'product_name': product_name,
                'product_id': product_id,
                'demand': 0,
                'demand_category': 'Low',
                'current_price': base_price,
                'suggested_price': base_price,
            })
            continue
        
        # Aggregate by date to get daily rentals for this product
        product_data = product_data.groupby('date')['rentals'].sum().reset_index()
        product_data.set_index('date', inplace=True)
        product_data = product_data.resample('D').sum().fillna(0)
        
        # Forecast for this product
        actual_data, predictions = simple_forecast(product_data)
        forecasted_demand = predictions.iloc[-1]  # Get the forecasted demand for the last predicted day
        
        # Adjust the price based on forecasted demand
        new_price = adjust_price(base_price, forecasted_demand)
        
        # Categorize the demand
        demand_category = categorize_demand(forecasted_demand)
        
        # Create a suggestion for this product
        suggestions.append({
            'product_name': product_name,
            'product_id': product_id,
            'demand': float(forecasted_demand),
            'demand_category': demand_category,
            'current_price': base_price,
            'suggested_price': new_price,
        })
    
    # Sort suggestions by demand (descending)
    suggestions.sort(key=lambda x: x['demand'], reverse=True)
    
    return suggestions

def get_all_product_suggestions():
    data = load_and_preprocess_data()
    
    if data.empty:
        return []
    
    # Fetch all products
    products = db.child("products").get().val()
    
    suggestions = []
    
    for product_id, product_data in products.items():
        product_name = product_data.get('product_name', 'Unknown Product')
        base_price = float(product_data.get('product_price', 0))
        
        # Filter the data for the current product
        product_data = data[data['product_id'] == product_id].copy()
        if product_data.empty:
            print(f"No rental data available for product {product_name}")
            continue
        
        # Aggregate by date to get daily rentals for this product
        product_data = product_data.groupby('date')['rentals'].sum().reset_index()
        product_data.set_index('date', inplace=True)
        product_data = product_data.resample('D').sum().fillna(0)
        
        # Forecast for this product
        actual_data, predictions = simple_forecast(product_data)
        forecasted_demand = predictions[-1]  # Get the forecasted demand for the last predicted day
        
        # Adjust the price based on forecasted demand
        new_price = adjust_price(base_price, forecasted_demand)
        
        # Categorize the demand
        demand_category = categorize_demand(forecasted_demand)
        
        # Create a suggestion for this product
        suggestions.append({
            'product_name': product_name,
            'product_id': product_id,
            'demand': forecasted_demand,
            'demand_category': demand_category,
            'current_price': base_price,
            'suggested_price': new_price,
        })
    
    # Sort suggestions by demand (descending)
    suggestions.sort(key=lambda x: x['demand'], reverse=True)
    
    return suggestions

def simple_forecast(data, days_to_predict=7):
    # Ensure data index is a datetime object
    if not isinstance(data.index, pd.DatetimeIndex):
        data.index = pd.to_datetime(data.index)
    
    if len(data) == 0:
        # Handle empty data case
        last_date = pd.Timestamp.now().date()
        future_dates = pd.date_range(start=last_date, periods=days_to_predict)
        predictions = [0] * days_to_predict
    else:
        last_date = data.index[-1]
        # Generate future dates by adding 1 day to the last date
        future_dates = pd.date_range(start=last_date + timedelta(days=1), periods=days_to_predict)

        # Simple moving average prediction
        window = min(7, len(data))  # Use up to 7 days for the moving average
        last_average = data['rentals'].rolling(window=window).mean().iloc[-1]
        predictions = [last_average] * days_to_predict
    
    return data, pd.Series(predictions, index=future_dates)

def visualize_results(actual_data, predictions):
    plt.figure(figsize=(12, 6))
    plt.plot(actual_data, label='Actual Data')
    plt.plot(predictions, label='Predictions', color='red')
    plt.title('Demand Forecast: Actual vs Predicted Rentals')
    plt.xlabel('Date')
    plt.ylabel('Number of Rentals')
    plt.legend()
    plt.show()

def adjust_price(base_price, forecasted_demand, threshold=4):
    if forecasted_demand > threshold:
        return base_price * 1.2  # Increase price by 20%
    return base_price

def categorize_demand(demand):
    if demand > 4:
        return "High"
    elif demand > 2:
        return "Medium"
    else:
        return "Low"

def get_all_product_suggestions():
    data = load_and_preprocess_data()
    
    if data.empty:
        return []
    
    # Fetch all products
    products = db.child("products").get().val()
    
    suggestions = []
    
    for product_id, product_data in products.items():
        product_name = product_data.get('product_name', 'Unknown Product')
        base_price = float(product_data.get('product_price', 0))
        
        # Filter the data for the current product
        product_data = data[data['product_id'] == product_id].copy()
        if product_data.empty:
            print(f"No rental data available for product {product_name}")
            suggestions.append({
                'product_name': product_name,
                'product_id': product_id,
                'demand': 0,
                'demand_category': 'Low',
                'current_price': base_price,
                'suggested_price': base_price,
            })
            continue
        
        # Aggregate by date to get daily rentals for this product
        product_data = product_data.groupby('date')['rentals'].sum().reset_index()
        product_data.set_index('date', inplace=True)
        product_data = product_data.resample('D').sum().fillna(0)
        
        # Forecast for this product
        actual_data, predictions = simple_forecast(product_data)
        forecasted_demand = predictions.iloc[-1] if not predictions.empty else 0  # Get the forecasted demand for the last predicted day
        
        # Adjust the price based on forecasted demand
        new_price = adjust_price(base_price, forecasted_demand)
        
        # Categorize the demand
        demand_category = categorize_demand(forecasted_demand)
        
        # Create a suggestion for this product
        suggestions.append({
            'product_name': product_name,
            'product_id': product_id,
            'demand': float(forecasted_demand),
            'demand_category': demand_category,
            'current_price': base_price,
            'suggested_price': new_price,
        })
    
    # Sort suggestions by demand (descending)
    suggestions.sort(key=lambda x: x['demand'], reverse=True)
    
    return suggestions

def get_products():
    try:
        products_data = db.child("products").get().val()
        if products_data is None:
            return []
        products = []
        for product_id, product_info in products_data.items():
            products.append({
                "id": product_id,
                "name": product_info.get("product_name", "Unknown Product")
            })
        return products
    except Exception as e:
        print(f"Error fetching products from Firebase: {str(e)}")
        raise

def main():
    # Load and preprocess data from Firebase
    data = load_and_preprocess_data()
    
    if data.empty:
        print("No data available for analysis.")
        return
    
    # Use simple forecast instead of ARIMA
    actual_data, predictions = simple_forecast(data)
    
    # Visualize results
    visualize_results(actual_data, predictions)
    
    # Adjust price based on forecast
    base_price = 100  # Base price of the tool
    forecasted_demand = predictions[-1]  # Forecasted demand for the last predicted day
    new_price = adjust_price(base_price, forecasted_demand)
    
    print(f"Forecast for the next 7 days:")
    for date, demand in predictions.items():
        print(f"Date: {date.date()}, Forecasted demand: {demand:.2f}")
    
    print(f"\nForecasted demand for {predictions.index[-1].date()}: {forecasted_demand:.2f}")
    print(f"Suggested new price based on forecasted demand: ${new_price:.2f}")

if __name__ == "__main__":
    main()
