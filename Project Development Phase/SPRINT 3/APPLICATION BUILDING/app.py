import os
import pathlib

import requests
from flask import Flask, render_template, request, redirect, url_for, session, abort
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from flask_mysqldb import MySQL
import MySQLdb.cursors
from authlib.integrations.flask_client import OAuth
import re
import joblib
import numpy as np
from datetime import date

app = Flask(__name__)
app.secret_key = 'your secret key'
 
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'IbmProjectDB'
 
mysql = MySQL(app)

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html') 
@app.route('/login', methods =['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user_accounts WHERE username = % s AND password = % s', (username, password, ))
        account = cursor.fetchone()
        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['email'] = account['email']
            msg = 'Logged in successfully !'
            return render_template('dashboard.html', msg = msg)
        else:
            msg = 'Incorrect username / password !'
    return render_template('login.html', msg = msg)
 
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.clear()
    return redirect(url_for('login'))
 
@app.route('/dashboard' , methods =['GET', 'POST'])
def dashboard():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    uname = str(session["username"])
    print(uname)
    cursor.execute("SELECT * FROM SEARCH_HISTORY WHERE USERNAME = '{}'".format(uname))
    rows = cursor.fetchall()
    print(rows)
    cursor.close()
    xAll_l = []
    cnt = 1
    for row in rows:
        print(row)
        rdict = {}
        rdict["COUNT"] = cnt
        rdict["SEARCH_DATE"] = row["SEARCH_DATE"]
        rdict["SEARCH_CITY"] = row["SEARCH_CITY"]
        rdict["THEORETICAL"] = row["THEORETICAL"]
        rdict["WIND_SPEED"] = row["WIND_SPEED"]
        rdict["POWER_OUTPUT"] = row["POWER_OUTPUT"]
        xAll_l.append(rdict)
        cnt += 1
    print(rows)
    xAlls = xAll_l
    return render_template('dashboard.html', xAlls=xAlls)

@app.route('/register', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form and 'confirm-password' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        confirmPassword = request.form['confirm-password']
        print(password, email, confirmPassword)
        if password != confirmPassword:
            msg = "Passwords doesn't match!"
            return render_template('register.html', msg = msg)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user_accounts WHERE username = % s', (username, ))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
        elif not username or not password or not email:
            msg = 'Please fill out the form !'
        else:
            cursor.execute('INSERT INTO user_accounts(username, password, email) VALUES (% s, % s, % s)', (username, password, email, ))
            mysql.connection.commit()
            msg = 'You have successfully registered !'
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('register.html', msg = msg)


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "35878162588-f4ok9ask9hek963cp9rt84hp2nsqg85k.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()

    return wrapper

@app.route("/login_with_google", methods=["POST", "GET"])
def login_with_google():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["username"] = id_info.get("name")
    session["email"] = id_info.get("email")
    print(session["username"])
    app.route("/dashboard")
    return redirect('/dashboard')

# Github login route
app.config['GITHUB_CLIENT_ID'] = "63c0fb7287951cbff862"
app.config['GITHUB_CLIENT_SECRET'] = "58d4295b3d2e6f382fac6f8bb5d01a291554a62d"
oauth = OAuth(app)

github = oauth.register (
  name = 'github',
    client_id = app.config["GITHUB_CLIENT_ID"],
    client_secret = app.config["GITHUB_CLIENT_SECRET"],
    access_token_url = 'https://github.com/login/oauth/access_token',
    access_token_params = None,
    authorize_url = 'https://github.com/login/oauth/authorize',
    authorize_params = None,
    api_base_url = 'https://api.github.com/',
    client_kwargs = {'scope': 'user:email'},
)


@app.route('/login/github')
def github_login():
    github = oauth.create_client('github')
    redirect_uri = url_for('github_authorize', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/login/github/authorize')
def github_authorize():
    github = oauth.create_client('github')
    token = github.authorize_access_token()
    resp = github.get('user').json()
    mail = resp['login']
    print(f"\n{resp}\n")
    print(f"\n{mail}\n")
    session['username'] = mail
    session['email'] = mail
    return render_template('dashboard.html')

@app.route('/predict', methods =['GET', 'POST'])
def predict():
    city=request.form.get('city')
    if city is None:
        city = 'Chennai'
    apikey="c9fa0fe134b266d709f02aee7fc59b50"
    url="http://api.openweathermap.org/data/2.5/weather?q="+city+"&appid="+apikey
    resp = requests.get(url)
    resp=resp.json()
    temp = round((resp["main"]["temp"])-273.15, 2)
    temp = str(temp) +" °C"
    humid = str(resp["main"]["humidity"])+" %"
    pressure = str(resp["main"]["pressure"])+" mmHG"
    wind_speed = round((resp["wind"]["speed"])*3.6, 2)
    wind_speed = str(wind_speed)+" Km/s"
    description = str(resp["weather"][0]["description"])
    session["city"] = city
    return render_template('predict.html', temp=temp, humid=humid, pressure=pressure, wind_speed=wind_speed, city=city, description=description)

model = joblib.load('./Power_Prediction.sav')
@app.route('/predictOut', methods =['GET', 'POST'])
def predictOut():
    inp1 = float(request.form['theory'])
    inp2 = float(request.form['wind'])
    int_features = [inp1, inp2]
    fin_features = [np.array(int_features)]
    prediction = model.predict(fin_features)
    output = round(prediction[0], 2) 
    print(output)
    today = date.today()
    d1 = today.strftime("%d/%m/%Y")
    print("d1 =", d1)
    city = session["city"]
    uname = session["username"]
    theo = str(inp1)
    wind = str(inp2)
    outp = str(output)
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("INSERT INTO SEARCH_HISTORY VALUES('{}', '{}', '{}', '{}', '{}', '{}')".format(uname, today, city, theo, wind, outp))
    mysql.connection.commit()
    return render_template('predict.html', prediction_text='The predicted Output is :{} KWh'.format(output))

if __name__ == "__main__":
    app.debug = True
    app.run()


    # https://stackoverflow.com/questions/68934033/for-loops-in-html-tables-for-var-in-var