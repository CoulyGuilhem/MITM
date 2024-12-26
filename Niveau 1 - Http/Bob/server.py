from flask import Flask, request, render_template_string

app = Flask(__name__)

login_page = """
<html>
<head><title>Login</title></head>
<body>
    <h1>Login</h1>
    <form method="POST" action="/login">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username"><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    return login_page

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username == "alice" and password == "password123":
        return "Welcome, Alice!"
    else:
        return "Invalid credentials!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)

