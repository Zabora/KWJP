from flask import Flask, request, redirect, url_for, render_template, session, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from Cryptodome.Random import get_random_bytes
from flask_mail import Mail, Message
from datetime import timedelta
from base64 import b64encode
import yaml
import re

app = Flask(__name__, static_folder='assets')

# Use config
config = yaml.load(open('./config/config.yaml'), Loader=yaml.FullLoader)
app.secret_key = config['secret_key']
app.permanent_session_lifetime = timedelta(days=2)

# Email regex, HTML5 spec
emailRegex = r"(^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$)"
emailRegexMsg = "Wprowadzono niepoprawny adres email."

# Password regex
passwordRegex = r"(^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,32}$)"
passwordRegexMsg = "Od 6 do 32 znakow. Musi zawierac cyfre, mala i duza litere"

# Database
db = yaml.load(open('./config/db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db['mysql_host']
app.config['MYSQL_USER'] = db['mysql_user']
app.config['MYSQL_PASSWORD'] = db['mysql_password']
app.config['MYSQL_DB'] = db['mysql_db']
mysql = MySQL(app)

# Mailer
app.config['MAIL_SERVER'] = config['mail']['host']
app.config['MAIL_PORT'] = config['mail']['port']
app.config['MAIL_USERNAME'] = config['mail']['username']
app.config['MAIL_PASSWORD'] = config['mail']['password']
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

# Bcrypt
bcrypt = Bcrypt(app)

@app.route("/")
def home():
  return render_template("index.html")

@app.route("/logout")
def logout():
  session.pop("user", None)
  return redirect(url_for("login"))

@app.route("/login", methods=["POST", "GET"])
def login():
  if request.method == "POST":
    user.email = request.form['email']
    user.password = request.form['password']

    # wszystkie pola mają być wypełnione
    if not user.email or not user.password:
      flash("Wszystkie pola są wymagane")
      return render_template("login.html", content={}), 400
    # walidacja email, specyfikacja HTML5
    if not re.match(emailRegex, user.email):
      flash(f"Email ma nieprawidłowy format\n{emailRegexMsg}")
      return render_template("login.html", content={}), 400
    # walidacja hasła
    if not re.match(passwordRegex, user.password):
      flash(f"Hasło ma nieprawidłowy format\n{passwordRegexMsg}")
      return render_template("login.html", content={"email": user.email}), 400
    
    cur = mysql.connection.cursor()
    results = cur.execute("""SELECT * FROM `users` WHERE `email` = %s""", [user.email])
    if results == 0:
      cur.close()
      flash("Hasło lub email są niepoprawne")
      return render_template("login.html", content={"email": user.email}), 400
    
    result = cur.fetchone()
    cur.close()
    if bcrypt.check_password_hash(result[2], user.password):
      session.permanent = True
      session["user"] = {
        "id": result[0],
        "email": user.email,
        "name": result[3],
        "privileges": result[4]
      }
      if result[4] == 'admin':
        return redirect('/dashboard')
      else:
        return redirect(f'users/{result[3]}')
    else:
      flash("Hasło lub email są niepoprawne")
      return render_template("login.html", content={"email": user.email}), 400
  else:
    if "user" in session:
      userData = session["user"]
      if userData.get("privileges") == 'admin':
        return redirect('/dashboard')
      else:
        return redirect(f"/users/{userData.get('name')}")
    else:
      return render_template("login.html", content={}), 200

@app.route("/register", methods=["POST", "GET"])
def register():
  if request.method == "POST":
    user.name = request.form['name']
    user.email = request.form['email']
    user.password = request.form['password']
    user.repassword = request.form['repassword']

    # wszystkie pola mają być wypełnione
    if not user.name or not user.email or not user.password or not user.repassword:
      flash("Wszystkie pola muszą być wypełnione")
      return render_template("register.html", content={"email": user.email, "name": user.name}), 400
    # name conajmniej 3 litery, max 32
    if len(user.name) < 3 or len(user.name) > 32:
      flash("Nazwa musi zawierać conajmniej 3 znaki i maksymalnie 32")
      return render_template("register.html", content={"email": user.email, "name": user.name}), 400
    # walidacja email, specyfikacja HTML5
    if not re.match(emailRegex, user.email):
      flash(f"Email ma niepoprawny format\n{emailRegexMsg}")
      return render_template("register.html", content={"email": user.email, "name": user.name}), 400
    # walidacja hasła
    if not re.match(passwordRegex, user.password):
      flash(f"Hasło ma niepoprawny format\n{passwordRegexMsg}")
      return render_template("register.html", content={"email": user.email, "name": user.name}), 400
    # sprawdzenie czy hasła są takie same
    if user.password != user.repassword:
      flash("Hasła muszą być takie same")
      return render_template("register.html", content={"email": user.email, "name": user.name}), 400
    
    cur = mysql.connection.cursor()
    results = cur.execute("""SELECT * FROM `users` WHERE `email` = %s""", [user.email])
    if results != 0:
      return render_template("register.html", content={}), 400
    
    pw_hash = bcrypt.generate_password_hash(user.password)
    cur.execute("""INSERT INTO users(`email`, `password`, `name`, `privileges`) VALUES(%s, %s, %s, %s)""", (user.email, pw_hash, user.name, 'user'))
    mysql.connection.commit()
    cur.close()

    return redirect('/login')
  else:
    return render_template("register.html", content={}), 400

@app.route("/recovery", methods=["POST", "GET"])
def recovery():
  if request.method == "POST":
    user.email = request.form['email']

    # Walidacja email
    if not re.match(emailRegex, user.email):
      flash(f"Email ma niepoprawny format\n{emailRegexMsg}")
      return render_template("recovery.html", content={"email": user.email}), 400
    
    cur = mysql.connection.cursor()
    results = cur.execute("""SELECT * FROM `users` WHERE `email` = %s""", [user.email])
    if results == 0:
      # Powinno się mówić, że takiego email nie ma w bazie, czy udawać że jest?
      cur.close()
      flash("Email nie występuje w bazie")
      return render_template("recovery.html", content={"email": user.email}), 400
    
    result = cur.fetchone()
    user.id = result[0]
    token = b64encode(get_random_bytes(94)).decode('utf-8')
    #'UPDATE `recovery_tokens` SET `state` = \'expired\' WHERE `state` = \'active\' AND `user_id` = ?'
    #'INSERT INTO `recovery_tokens` (`user_id`, `token`, `dbtable`) VALUES (?, ?, ?)'
    cur.execute("""UPDATE `recovery_tokens` SET `state` = %s WHERE `state` = %s AND `user_id` = %s""", ('expired', 'active', user.id))
    cur.execute("""INSERT INTO `recovery_tokens` (`user_id`, `token`) VALUES (%s, %s)""", (user.id, token))
    mysql.connection.commit()
    cur.close()

    msg = Message('Reset password', sender = config['mail']['username'], recipients = [user.email])
    msg.html = render_template('mail_reset_password.html', content={"token": token})
    #msg.body = f'<!DOCTYPE html><html><body><b>Token</b>: {token}<br><br><a href="http://127.0.0.1:5000/resetpassword?token={token}">reset</a></body></html>'
    mail.send(msg)

    return redirect('/login')
  else:
    return render_template("recovery.html"), 200

@app.route("/resetpassword", methods=["POST", "GET"])
def reset():
  if request.method == "POST":
    pass
  else:
    if request.args.get('token'):
      return render_template("reset_password.html", content={"token": request.args.get('token')}), 200
    else:
      return render_template("reset_password.html", content={}), 200

@app.route("/users/<user>")
def user(user):
  if "user" in session:
    userData = session["user"]
    if userData.get("name") != user:
      return redirect(f"/users/{userData.get('name')}")
    
    return render_template("user.html", content=userData), 200
  else:
    flash("Zostałeś wylogowany")
    return redirect("/login")

@app.route("/flashcards/<id>")
def flashcard(id):
  return f"<p>This is flashcards {id}</p>"

@app.route("/flashcards/<id>/create", methods=["POST", "GET"])
def update(id):
  if request.method == "POST":
    return redirect(url_for("/"))
  else:
    return "<p>This is reset password page GET METHOD</p>"

@app.route("/learn/<id>")
def learn(id):
  return f"<p>This is learn {id}</p>"

@app.route("/dashboard")
def dashboard():
  return "<p>This is admin dashboard</p>"

if __name__ == "__main__":
  app.run(debug=True)
