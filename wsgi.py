from app import create_app

app = create_app()

@app.route('/health')
def health_check():
    return 'OK', 200

if __name__ == '__main__':
    app.run()
