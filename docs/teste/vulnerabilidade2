from flask import Flask, request
import sqlite3
app = Flask(__name__)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
   
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
   
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)
   
    user = cursor.fetchone()
   
    if user:
        return "Login bem-sucedido!"
    else:
        return "Credenciais inválidas.", 401


if __name__ == '__main__':
    app.run()
