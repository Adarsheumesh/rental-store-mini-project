import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
import string

def generate_dummy_data(num_orders=100, start_date='2023-01-01', end_date='2023-12-31'):
    start = pd.to_datetime(start_date)
    end = pd.to_datetime(end_date)
    date_range = pd.date_range(start=start, end=end)

    orders = {}
    for i in range(num_orders):
        order_date = pd.Timestamp(np.random.choice(date_range))
        num_items = np.random.randint(1, 4)  # 1 to 3 items per order
        
        items = []
        for _ in range(num_items):
            rent_from = order_date.to_pydatetime()
            rent_to = rent_from + timedelta(days=np.random.randint(1, 8))  # 1 to 7 day rental
            items.append({
                "item_total": np.random.randint(500, 5000) / 100,  # Random price between $5 and $50
                "product_id": f"PROD-{np.random.randint(1000, 9999)}",
                "rent_from": rent_from.strftime('%Y-%m-%d'),
                "rent_to": rent_to.strftime('%Y-%m-%d'),
                "rental_days": (rent_to - rent_from).days
            })
        
        order_total = sum(item['item_total'] for item in items)
        
        order = {
            "created_at": order_date.strftime('%Y-%m-%dT%H:%M:%S.%f'),
            "items": items,
            "order_total": order_total,
            "payment_intent_id": f"pi_{''.join(np.random.choice(list(string.ascii_letters + string.digits), 24))}",
            "shipping_address": f"{np.random.randint(1, 1000)} Main St, City, State, ZIP",
            "shipping_address2": "",
            "status": np.random.choice(['paid', 'pending'], p=[0.9, 0.1]),
            "updated_at": (order_date + pd.Timedelta(minutes=np.random.randint(5, 60))).strftime('%Y-%m-%dT%H:%M:%S.%f'),
            "use_different_shipping": False,
            "user_id": f"USER-{np.random.randint(1000, 9999)}"
        }
        
        orders[f"ORDER-{i+1}"] = order

    return orders

# Generate dummy data
dummy_data = generate_dummy_data()

# Save to JSON file
json_filename = 'dummy_orders.json'
with open(json_filename, 'w') as json_file:
    json.dump(dummy_data, json_file, indent=2)

print(f"Dummy data saved to {json_filename}")

# Display a sample order
sample_order_id = next(iter(dummy_data))
print("\nSample Order:")
print(json.dumps(dummy_data[sample_order_id], indent=2))

# Create a DataFrame for analysis
df = pd.DataFrame([
    {
        'date': pd.to_datetime(order['created_at']),
        'rentals': len(order['items'])
    }
    for order in dummy_data.values()
])

print("\nInitial DataFrame:")
print(df.head())
print(df.dtypes)

# Set 'date' as index
df.set_index('date', inplace=True)

print("\nDataFrame after setting index:")
print(df.head())
print(df.index)

# Group by date and sum rentals
df = df.groupby(df.index.date)['rentals'].sum().reset_index()
df['date'] = pd.to_datetime(df['date'])
df.set_index('date', inplace=True)

print("\nDataFrame after grouping:")
print(df.head())
print(df.index)

# Resample to daily frequency, filling missing dates with 0
df = df.resample('D').sum().fillna(0)

print("\nFinal DataFrame:")
print(df.head())
print(df.index)

print("\nDataFrame Info:")
df.info()

# Save DataFrame to CSV
csv_filename = 'dummy_rental_data.csv'
df.to_csv(csv_filename)
print(f"\nDataFrame saved to {csv_filename}")
