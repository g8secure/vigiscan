import requests
import sqlite3

s = requests.Session()
res = s.post('http://localhost:5000/login', data={'username':'Abrahamdagr8', 'password':'password'})
print("Login status:", res.status_code)

res2 = s.post('http://localhost:5000/api/save_language', json={'language': 'fr'})
print("Save lang status:", res2.status_code, res2.text)

c = sqlite3.connect('users.db').cursor()
c.execute('SELECT settings FROM users WHERE username="Abrahamdagr8"')
print("Settings:", c.fetchone())
