from flask import Flask, request, redirect, url_for, render_template, session, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from Cryptodome.Random import get_random_bytes
from flask_mail import Mail, Message
from datetime import datetime, timedelta
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
passwordRegexMsg = "Od 6 do 32 znaków. Musi zawierać cyfre, małą i dużą litere"

# Database
db = yaml.load(open('./config/db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db['mysql_host']
app.config['MYSQL_USER'] = db['mysql_user']
app.config['MYSQL_PASSWORD'] = db['mysql_password']
app.config['MYSQL_DB'] = db['mysql_db']
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
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
    
    try:
      cur = mysql.connection.cursor()
      results = cur.execute("""SELECT * FROM `users` WHERE `email` = %s""", [user.email])
    except Exception as ex:
      return render_template("error.html", content={"code": 500, "error": "Connect"}), 500
    else:
      if results == 0:
        cur.close()
        flash("Hasło lub email są niepoprawne")
        return render_template("login.html", content={"email": user.email}), 400
      
      result = cur.fetchone()
      cur.close()
      if result["state"] == "banned":
        flash("Twoje konto jest zablokowane")
        return render_template("login.html", content={}), 403

      if bcrypt.check_password_hash(result["password"], user.password):
        session.permanent = True
        session["user"] = {
          "id": result["id"],
          "email": user.email,
          "name": result["name"],
          "privileges": result["privileges"],
          "state": result["state"]
        }

        if result["privileges"] == 'admin':
          return redirect('/dashboard')
        else:
          return redirect(f'users/{result["name"]}')
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
    
    try:
      cur = mysql.connection.cursor()
      results = cur.execute("""SELECT * FROM `users` WHERE `email` = %s""", [user.email])
    except Exception as ex:
      return render_template("error.html", content={"code": 500, "error": "Connect/Cursor"}), 500
    else:
      if results != 0:
        cur.close()
        # Powinno się mówić, że takiego email nie ma w bazie, czy udawać że jest?
        flash("Email jest już zajęty")
        return render_template("register.html", content={}), 400
      
      try:
        pw_hash = bcrypt.generate_password_hash(user.password)
        cur.execute("""INSERT INTO users(`email`, `password`, `name`, `privileges`) VALUES(%s, %s, %s, %s)""", (user.email, pw_hash, user.name, 'user'))
      except Exception as ex:
        return render_template("error.html", content={"code": 500, "error": "Connect/Duplicate"}), 500
      else:
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
    
    # Tu chyba przyda się stworzyć Thread żeby klient nie czekał
    # bo możliwe że bardzo długo to trwa, a klient i tak ma czekac na maila
    # TODO:

    try:
      cur = mysql.connection.cursor()
      results = cur.execute("""SELECT * FROM `users` WHERE `email` = %s""", [user.email])
    except Exception as ex:
      return render_template("error.html", content={"code": 500, "error": "Connect/Cursor"}), 500
    else:
      if results == 0:
        # Powinno się mówić, że takiego email nie ma w bazie, czy udawać że jest?
        cur.close()
        flash("Email nie występuje w bazie")
        return render_template("recovery.html", content={"email": user.email}), 400

      try:
        result = cur.fetchone()
        user.id = result["id"]
        token = b64encode(get_random_bytes(94)).decode('utf-8')
        token = token.replace("+", "-").replace("/", "_") # trzeba zrobic url safe
        cur.execute("""UPDATE `recovery_tokens` SET `state` = %s WHERE `state` = %s AND `user_id` = %s""", ('expired', 'active', user.id))
        cur.execute("""INSERT INTO `recovery_tokens` (`user_id`, `token`) VALUES (%s, %s)""", (user.id, token))
        mysql.connection.commit()
        cur.close()
      except Exception as ex:
        return render_template("error.html", content={"code": 500, "error": "Connect/Update/Insert"}), 500
      else:
        msg = Message('Reset password', sender = config['mail']['username'], recipients = [user.email])
        msg.html = render_template("mail_reset_password.html", content={"token": token})
        mail.send(msg)

        return redirect('/login')
  else:
    return render_template("recovery.html"), 200

@app.route("/resetpassword", methods=["POST", "GET"])
def resetpassword():
  if request.method == "POST":
    user.password = request.form['password']
    user.repassword = request.form['repassword']
    user.token = request.form['token']

    # wszystkie pola mają być wypełnione
    if not user.password or not user.repassword:
      flash("Wszystkie pola muszą być wypełnione")
      return render_template("reset_password.html", content={"token": user.token}), 400
    # walidacja hasła
    if not re.match(passwordRegex, user.password):
      flash(f"Hasło ma niepoprawny format\n{passwordRegexMsg}")
      return render_template("reset_password.html", content={"token": user.token}), 400
    # sprawdzenie czy hasła są takie same
    if user.password != user.repassword:
      flash("Hasła muszą być takie same")
      return render_template("reset_password.html", content={"token": user.token}), 400

    try:
      cur = mysql.connection.cursor()
      results = cur.execute("""SELECT * FROM `recovery_tokens` WHERE `state` = \'active\' AND `token` = %s""", [user.token])
    except Exception as ex:
      return render_template("error.html", content={"code": 500, "error": "Connect/Cursor"}), 500
    else:
      if results == 0:
        cur.close()
        flash("Token wygasł lub jest niepoprawny")
        return render_template("reset_password.html", content={}), 400

      result = cur.fetchone()
      user.id = result["id"]
      time = result["gen_time"]
      if (time + timedelta(days=1)) < datetime.now():
        try:
          cur.execute("""UPDATE `recovery_tokens` SET `state` = \'expired\' WHERE `state` = \'active\' AND `token` = %s""", [user.token])
        except Exception as ex:
          return render_template("error.html", content={"code": 500, "error": "Connect/Update/Expired"}), 500
        else:
          mysql.connection.commit()
          cur.close()
          flash("Token wygasł lub jest niepoprawny")
          return render_template("reset_password.html", content={}), 400

      try:
        cur.execute("""UPDATE `recovery_tokens` SET `state` = \'expired\' WHERE `state` = \'active\' AND `token` = %s""", [user.token])
        pw_hash = bcrypt.generate_password_hash(user.password)
        cur.execute("""UPDATE `users` SET `password` = %s WHERE `id` = %s""", (pw_hash, user.id))
      except Exception as ex:
        return render_template("error.html", content={"code": 500, "error": "Connect/Update"}), 500
      else:
        mysql.connection.commit()
        cur.close()
        return render_template("redirect.html", content={"time": 5000, "msg": "Hasło zostało zmienione. Za 5 sekund zostaniesz przekierowany na strone logowania"})
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

@app.route("/flashcards")
def flashcards():
  if "user" in session:
    try:
      cur = mysql.connection.cursor()
      if request.args.get('search'):
        results = cur.execute("""SELECT * FROM `flashcard_sets` WHERE `set_name` LIKE %s AND `state` = 'active'""", ['%' + request.args.get('search') + '%'])
      else:
        results = cur.execute("""SELECT * FROM `flashcard_sets` WHERE `state` = 'active'""")
    except Exception as ex:
      return render_template("error.html", content={"code": 500, "error": "Connect"}), 500
    else:
      result = cur.fetchall()
      cur.close()

      return render_template("flashcard_sets.html", content={"flashcard_sets": result, "type": "user"}), 200
  else:
    flash("Musisz być zalogowany, aby przeglądać zestawy")
    return redirect("login")

@app.route("/flashcards/<id>")
def flashcard(id):
  if "user" in session:
    try:
      cur = mysql.connection.cursor()
      results = cur.execute("""SELECT * FROM `flashcard_sets` WHERE `set_id` = %s AND `state` = 'active'""", [id])
    except Exception as ex:
      return render_template("error.html", content={"code": 500, "error": "Connect"}), 500
    else:
      if results == 0:
        cur.close()
        return render_template("error.html", content={"code": 404, "error": "Not Found"}), 404
      
      result1 = cur.fetchone()

      try:
        results = cur.execute("""SELECT * FROM `flashcard` WHERE `set_id` = %s""", [id])
      except Exception as ex:
        return render_template("error.html", content={"code": 500, "error": "Connect"}), 500
      else:
        if results == 0:
          return render_template("error.html", content={"code": 204, "error": "Zestaw jest pusty"}), 204

        result2 = cur.fetchall()
        cur.close()

        return render_template("flashcard.html", content={"flashcard_sets": result1, "flashcard": result2}), 200
  else:
    flash("Musisz być zalogowany, aby przeglądać fiszki")
    return redirect("login")

@app.route("/flashcards/<id>/create", methods=["POST", "GET"])
def update(id):
  if "user" in session:
    if request.method == "POST":
      return f"<p>POST This is update {id}</p>"
    else:
      return f"<p>GET This is update {id}</p>"
  else:
    flash("Musisz być zalogowany, aby tworzyć/edytować fiszki")
    return redirect("login")

@app.route("/learn/<id>")
def learn(id):
  if "user" in session:
    return f"<p>GET This is learn {id}</p>"
  else:
    flash("Musisz być zalogowany, aby ...")
    return redirect("login")

@app.route("/dashboard")
def dashboard():
  if "user" in session:
    userData = session["user"]
    if userData.get("privileges") == 'admin':
      return render_template("dashboard.html"), 200
    else:
      return redirect("login")
  else:
    return redirect("login")

@app.route("/dashboard/users")
def users():
  if "user" in session:
    userData = session["user"]
    if userData.get("privileges") == 'admin':
      try:
        cur = mysql.connection.cursor()
        cur.execute("""SELECT * FROM `users`""")
      except Exception as ex:
        return render_template("error.html", content={"code": 500, "error": "Connect"}), 500
      else:
        results = cur.fetchall()
        cur.close()
        return render_template("users.html", content = results)
    else:
      return redirect("login")
  else:
    return redirect("login")

@app.route("/dashboard/flashcards")
def flashcardsAdmin():
  if "user" in session:
    userData = session["user"]
    if userData.get("privileges") == 'admin':
      try:
        cur = mysql.connection.cursor()
        if request.args.get('search'):
          results = cur.execute("""SELECT * FROM `flashcard_sets` WHERE `set_name` LIKE %s""", ['%' + request.args.get('search') + '%'])
        else:
          results = cur.execute("""SELECT * FROM `flashcard_sets`""")
      except Exception as ex:
        return render_template("error.html", content={"code": 500, "error": "Connect"}), 500
      else:
        result = cur.fetchall()
        cur.close()

        return render_template("flashcard_sets.html", content={"flashcard_sets": result, "type": "admin"}), 200
    else:
      return redirect("login")
  else:
    return redirect("login")

@app.route("/dashboard/flashcards/<id>/lock")
def lockFlashcard(id):
  if "user" in session:
    userData = session["user"]
    if userData.get("privileges") == 'admin':
      try:
        cur = mysql.connection.cursor()
        results = cur.execute("""UPDATE `flashcard_sets` SET `state` = 'banned' WHERE `set_id` = %s""", [id])
      except Exception as ex:
        return render_template("error.html", content={"code": 500, "error": "Connect/Upadate ban"}), 500
      else:
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('flashcardsAdmin'))
    else:
      return redirect("login")
  else:
    return redirect("login")

@app.route("/dashboard/flashcards/<id>/unlock")
def unlockFlashcard(id):
  if "user" in session:
    userData = session["user"]
    if userData.get("privileges") == 'admin':
      try:
        cur = mysql.connection.cursor()
        results = cur.execute("""UPDATE `flashcard_sets` SET `state` = 'active' WHERE `set_id` = %s""", [id])
      except Exception as ex:
        return render_template("error.html", content={"code": 500, "error": "Connect/Upadate ban"}), 500
      else:
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('flashcardsAdmin'))
    else:
      return redirect("login")
  else:
    return redirect("login")

@app.route("/dashboard/users/<id>/lock")
def lock(id):
  if "user" in session:
    userData = session["user"]
    if userData.get("privileges") == 'admin':
      try:
        cur = mysql.connection.cursor()
        results = cur.execute("""UPDATE `users` SET `state` = 'banned' WHERE `id` = %s""", [id])
      except Exception as ex:
        return render_template("error.html", content={"code": 500, "error": "Connect/Upadate ban"}), 500
      else:
        mysql.connection.commit()
        cur.close()
        return redirect("/dashboard/users")
    else:
      return redirect("login")
  else:
    return redirect("login")

@app.route("/dashboard/users/<id>/unlock")
def unlock(id):
  if "user" in session:
    userData = session["user"]
    if userData.get("privileges") == 'admin':
      try:
        cur = mysql.connection.cursor()
        results = cur.execute("""UPDATE `users` SET `state` = 'active' WHERE `id` = %s""", [id])
      except Exception as ex:
        return render_template("error.html", content={"code": 500, "error": "Connect/Upadate unban"}), 500
      else:
        mysql.connection.commit()
        cur.close()
        return redirect("/dashboard/users")
    else:
      return redirect("login")
  else:
    return redirect("login")

if __name__ == "__main__":
  app.run(debug=True)
