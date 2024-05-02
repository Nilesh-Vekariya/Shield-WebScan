# Shield-WebScan

To run a Flask application using a Python file, you typically define your Flask routes and configurations within the Python file, then run the Flask development server. Here's a step-by-step guide:

1) Install Flask:Before you start, make sure you have Flask installed. You can install it via pip:

```
pip install Flask
```

2) Create a Python File:Create a Python file (let's name it app.py) in your project directory.
Write Your Flask Application:In app.py, you define your Flask application. Here's a basic example:
python

```
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run(debug=True)
```
  In this example, we create a Flask application with a single route (/) that returns "Hello, World!" when accessed.

3) Run Your Flask Application:To run your Flask application, simply execute the app.py file:
```
python app.py
```
This starts the Flask development server. You should see output indicating that the server is running.
Access Your Flask Application:Once the server is running, you can access your Flask application by opening a web browser and navigating to http://localhost:5000 or http://127.0.0.1:5000.
