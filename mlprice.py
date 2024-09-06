import pyrebase
import pandas as pd
import numpy as np
from statsmodels.tsa.arima.model import ARIMA
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import json

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
    
    # Print the structure of the first order for debugging
    print("Sample order structure:")
    print(json.dumps(list(orders.values())[0], indent=2))
    
    # Prepare data for time series analysis
    data = []
    for order_id, order in orders.items():
        order_date = order.get('created_at')  # Use 'created_at' instead of 'order_date'
        if order_date:
            try:
                date = pd.to_datetime(order_date).date()
                items = order.get('items', [])
                total_rentals = sum(1 for item in items)  # Count each item as one rental
                data.append({
                    'date': date,
                    'rentals': total_rentals
                })
            except ValueError as e:
                print(f"Error processing order date for order {order_id}: {e}")
                print(f"Order data: {order}")
    
    if not data:
        print("No valid order data found.")
        return pd.DataFrame()  # Return an empty DataFrame if no valid data is found
    
    # Convert to DataFrame and aggregate by date
    df = pd.DataFrame(data)
    print("DataFrame head:")
    print(df.head())
    print("DataFrame info:")
    df.info()
    
    df['date'] = pd.to_datetime(df['date'])  # Ensure date is datetime
    df = df.groupby('date')['rentals'].sum().reset_index()
    df.set_index('date', inplace=True)
    df = df.resample('D').sum().fillna(0)
    
    return df

def simple_forecast(data, days_to_predict=7):
    if len(data) < 2:
        # If we have less than 2 data points, use the last value (or 0 if no data)
        last_value = data.iloc[-1]['rentals'] if len(data) > 0 else 0
        future_dates = pd.date_range(start=data.index[-1] + timedelta(days=1), periods=days_to_predict)
        predictions = pd.Series([last_value] * days_to_predict, index=future_dates)
    else:
        # Use a simple moving average
        window = min(7, len(data))  # Use up to 7 days for the moving average
        last_average = data['rentals'].rolling(window=window).mean().iloc[-1]
        future_dates = pd.date_range(start=data.index[-1] + timedelta(days=1), periods=days_to_predict)
        predictions = pd.Series([last_average] * days_to_predict, index=future_dates)
    
    return data, predictions

def visualize_results(actual_data, predictions):
    plt.figure(figsize=(12, 6))
    plt.plot(actual_data, label='Actual Data')
    plt.plot(predictions, label='Predictions', color='red')
    plt.title('Demand Forecast: Actual vs Predicted Rentals')
    plt.xlabel('Date')
    plt.ylabel('Number of Rentals')
    plt.legend()
    plt.show()

def adjust_price(base_price, forecasted_demand, threshold=20):
    if forecasted_demand > threshold:
        return base_price * 1.2  # Increase price by 20%
    return base_price

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
