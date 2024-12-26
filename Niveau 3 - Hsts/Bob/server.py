from flask import Flask, request, Response

app = Flask(__name__)

# Forcer HSTS sur toutes les connexions HTTPS
@app.after_request
def apply_hsts(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    return response

@app.route('/')
def index():
    return '''
    <html>
    <body>
        <h1>Login</h1>
        <form method="POST" action="/login">
            <label>Username:</label>
            <input type="text" name="username"><br>
            <label>Password:</label>
            <input type="password" name="password"><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    '''

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username == "alice" and password == "password123":
        return "Welcome Alice!"
    return "Invalid credentials."

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=443, ssl_context=('../openssl_cert/192.168.89.100.pem', '../openssl_cert/192.168.89.100-key.pem'))
