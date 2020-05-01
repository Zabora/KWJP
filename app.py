from flask import Flask, request, redirect, url_for, render_template

app = Flask(__name__)

@app.route("/")
def home():
  return render_template("index.html")

@app.route("/login", methods=["POST", "GET"])
def login():
  if request.method == "POST":
    return "<p>This is login page POST METHOD</p>"
  else:
    return "<p>This is login page GET METHOD</p>"

@app.route("/register", methods=["POST", "GET"])
def register():
  if request.method == "POST":
    return "<p>This is register page POST METHOD</p>"
  else:
    return "<p>This is register page GET METHOD</p>"

@app.route("/recovery", methods=["POST", "GET"])
def recovery():
  if request.method == "POST":
    return "<p>This is recovery page POST METHOD</p>"
  else:
    return "<p>This is recovery page GET METHOD</p>"

@app.route("/resetpassword", methods=["POST", "GET"])
def reset():
  if request.method == "POST":
    return "<p>This is reset password page POST METHOD</p>"
  else:
    return "<p>This is reset password page GET METHOD</p>"

@app.route("/users/<user>")
def user(user):
  return f"<p>Hello {user}</p>"

@app.route("/flashcards/<id>")
def flashcard(id):
  return f"<p>This is flashcards {id}</p>"
  
@app.route("/learn/<id>")
def learn(id):
  return f"<p>This is learn {id}</p>"

@app.route("/flashcards/<id>/create", methods=["POST", "GET"])
def update(id):
  if request.method == "POST":
    return redirect(url_for("/"))
  else:
    return "<p>This is reset password page GET METHOD</p>"

@app.route("/dashboard")
def dashboard():
  return "<p>This is admin dashboard</p>"

if __name__ == "__main__":
  app.run(debug=True)
