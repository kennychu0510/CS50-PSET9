import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from pytz import timezone
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Create a table called transactions to record all the transactions from user
db.execute("CREATE TABLE IF NOT EXISTS transactions (user_id INTEGER, symbol TEXT NOT NULL, shares INTEGER, price NUMBER, timestamp TEXT, type TEXT NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id))")

# Create a table called stocks storing user_id and the stocks they own
db.execute("CREATE TABLE IF NOT EXISTS stocks_owned (user_id INTEGER, symbol TEXT NOT NULL, name TEXT NOT NULL, shares INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))")


# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    profile = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    stocks = db.execute("SELECT * FROM stocks_owned WHERE user_id = ?", session["user_id"])

    # Update the price of each stock using lookup function and sum the total value of all stocks including cash
    stockPrice = {}
    total = profile[0]["cash"]

    for stock in stocks:
        lookUpStock = lookup(stock["symbol"])
        stockPrice[stock["symbol"]] = lookUpStock["price"]
        total += lookUpStock["price"] * stock["shares"]

    return render_template("index.html", stocks=stocks, profile=profile, stockPrice=stockPrice, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # When user buys a stock
    if request.method == "POST":

        # Ensure stock is submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        # Check if lookup is successful
        if lookup(request.form.get("symbol")) == None:
            return apology("invalid symbol", 400)

        # Check if number of shares is a number
        if not request.form.get("shares").isnumeric():
            return apology("shares is not a number", 400)

        # Check if number of shares is an integer
        shares = float(request.form.get("shares"))
        if not shares.is_integer():
            return apology("shares is not an integer", 400)

        # Check if number of shares is appropriate
        if int(request.form.get("shares")) < 1:
            return apology("invalid number of shares", 400)

        stock = lookup(request.form.get("symbol"))
        shares = int(request.form.get("shares"))
        symbol = stock["symbol"]
        price = float(stock["price"])
        user_id = session["user_id"]
        cash = int(db.execute("SELECT * FROM users WHERE id = ?", user_id)[0]["cash"])

        # Check if enough cash to buy stock
        if price * shares > cash:
            return apology("not enough money", 403)

        now = datetime.now(timezone("Hongkong"))
        # Update the transactions table
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, timestamp, type) VALUES(?, ?, ?, ?, ?, ?)", user_id, symbol, shares, price, now, "BUY")

        # Update the stocks_owned table

        # If user do not own the stock before, insert new purchase info
        if len(db.execute("SELECT * FROM stocks_owned WHERE user_id = ? AND symbol = ?", user_id, symbol)) == 0:
            db.execute("INSERT INTO stocks_owned (user_id, symbol, name, shares) VALUES(?, ?, ?, ?)", user_id, symbol, stock["name"], shares)

        # If user have bought the stock before
        else:
            shares_currently_owned = db.execute("SELECT shares FROM stocks_owned WHERE user_id = ? AND symbol = ?", user_id, symbol)[0]["shares"]
            shares_currently_owned += shares
            db.execute("UPDATE stocks_owned SET shares = ? WHERE user_id = ? AND symbol = ?", shares_currently_owned, user_id, symbol)

        # Updating the cash of user after purchase of stock
        cash = cash - (price * shares)
        db.execute("UPDATE users SET cash = ?", cash)

        # Display message
        name = stock["name"]
        message = f"You have bought {shares} shares of {name} at {usd(price)} per share"
        flash(message)

        return redirect("/")

    # When user enters the buy page
    return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # When user submits a quote
    if request.method == "POST":

        # Ensure quote is submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        # Check if lookup is successful
        elif lookup(request.form.get("symbol")) == None:
            return apology("invalid symbol", 400)

        quote = lookup(request.form.get("symbol"))

        return render_template("quoted.html", quote=quote)

    # Display a form for user to quote
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # When user submits the register form
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmation was submitted
        if not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure confirmation matches password
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Check if username is already taken
        if len(rows) == 1:
            return apology("username already taken", 400)

        # Register form is OK, store username and password to database
        username = request.form.get("username")
        password = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password)

        # Redirect to homepage after registered
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        session["user_id"] = rows[0]["id"]

        # Display message
        flash("You have registered!")
        return redirect("/")

    # When arriving at register page
    return render_template("register.html")




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # When user sells a quote
    if request.method == "POST":

        # Ensure symbol is submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        symbol = request.form.get("symbol")
        shares_owned = (db.execute("SELECT shares FROM stocks_owned WHERE user_id = ? AND symbol = ?", session["user_id"], symbol))[0]["shares"]

        # Check if user owns the shares
        if shares_owned == 0:
            return apology("you do not own any shares", 400)

        # Check if number of shares to sell is appropriate
        if (int(request.form.get("shares")) < 1 or int(request.form.get("shares")) > shares_owned):
            return apology("invalid shares to sell", 400)

        shares = int(request.form.get("shares"))
        now = datetime.now(timezone("Hongkong"))
        new_shares = shares_owned - shares
        price = lookup(symbol)["price"]
        # Record the sell in the transactions table
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, timestamp, type) VALUES(?, ?, ?, ?, ?, ?)", session["user_id"], symbol, shares, price, now, "SELL")

        # Update shares_owned table for user
        db.execute("UPDATE stocks_owned SET shares = ? WHERE user_id = ? AND symbol = ?", new_shares, session["user_id"], symbol)

        # Delete row in shares_owned table if user has sold all the shares
        if (db.execute("SELECT shares FROM stocks_owned WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)[0]["shares"] == 0):
            db.execute("DELETE FROM stocks_owned WHERE symbol = ? AND user_id = ?", symbol, session["user_id"])

        # Add cash after selling shares
        cash = float((db.execute("SELECT * FROM users WHERE id = ?", session["user_id"]))[0]["cash"])
        cash = cash + (price * shares)
        db.execute("UPDATE users SET cash = ?", cash)

        # display message
        name = lookup(symbol)["name"]
        message = f"You have sold {shares} shares of {name} at {usd(price)} per share"
        flash(message)
        return redirect("/")

    # When user arrives the sell page
    stocks = db.execute("SELECT * FROM stocks_owned WHERE user_id = ?", session["user_id"])

    return render_template("sell.html", stocks=stocks)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Change password"""

    # When user submits the register form
    if request.method == "POST":

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirm password was submitted
        if not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure password is correct
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if not check_password_hash(user[0]["hash"], request.form.get("password")):
            return apology("wrong password", 403)

        # Ensure confirmation matches password
        if request.form.get("newPassword") != request.form.get("confirmation"):
            return apology("passwords do not match", 403)

        # Update new password
        newPassword = generate_password_hash(request.form.get("newPassword"))
        db.execute("UPDATE users SET hash = ? WHERE id = ?", newPassword, session["user_id"])

        flash("Password Changed")
        return redirect("/")

    # When arriving at register page
    return render_template("settings.html")

@app.route("/topUp", methods=["GET", "POST"])
@login_required
def topUp():
    """Top up cash"""

    # When user submits the register form
    if request.method == "POST":

        # Ensure amount is submitted
        if not request.form.get("amount"):
            return apology("must insert amount", 400)

        # Ensure amount is submitted
        if (float(request.form.get("amount")) < 0):
            return apology("amount must be positive", 403)

        # Top up cash for user
        amount = float(request.form.get("amount"))
        cash = float((db.execute("SELECT * FROM users WHERE id = ?", session["user_id"]))[0]["cash"])
        cash = cash + amount
        db.execute("UPDATE users SET cash = ?", cash)
        amount = usd(amount)
        message = f"{amount} added"
        flash(message)
        return redirect("/")
    # When arriving at register page
    return render_template("topUp.html")


@app.route("/buyThis", methods=["GET", "POST"])
@login_required
def buyThis():
    """Buy specified stock"""

    # When user buys the specified stock
    if request.method == "POST":
        # Check if lookup is successful
        if lookup(request.form.get("symbol")) == None:
            return apology("invalid symbol", 400)

        # Check if number of shares is appropriate
        if int(request.form.get("shares")) < 1:
            return apology("invalid number of shares", 403)

        stock = lookup(request.form.get("symbol"))
        symbol = stock["symbol"]
        shares = int(request.form.get("shares"))
        price = float(stock["price"])
        user_id = session["user_id"]
        cash = int(db.execute("SELECT * FROM users WHERE id = ?", user_id)[0]["cash"])

        # Check if enough cash to buy stock
        if price * shares > cash:
            return apology("not enough money", 403)

        now = datetime.now(timezone("Hongkong"))
        # Update the transactions table
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, timestamp, type) VALUES(?, ?, ?, ?, ?, ?)", user_id, symbol, shares, price, now, "BUY")

        # Update the stocks_owned table

        # If user do not own the stock before, insert new purchase info
        if len(db.execute("SELECT * FROM stocks_owned WHERE user_id = ? AND symbol = ?", user_id, symbol)) == 0:
            db.execute("INSERT INTO stocks_owned (user_id, symbol, name, shares) VALUES(?, ?, ?, ?)", user_id, symbol, stock["name"], shares)

        # If user have bought the stock before
        else:
            shares_currently_owned = db.execute("SELECT shares FROM stocks_owned WHERE user_id = ? AND symbol = ?", user_id, symbol)[0]["shares"]
            shares_currently_owned += shares
            db.execute("UPDATE stocks_owned SET shares = ? WHERE user_id = ? AND symbol = ?", shares_currently_owned, user_id, symbol)

        # Updating the cash of user after purchase of stock
        cash = cash - (price * shares)
        db.execute("UPDATE users SET cash = ?", cash)

        # Display message
        name = stock["name"]
        message = f"You have bought {shares} shares of {name} at {usd(price)} per share"
        flash(message)

        return redirect("/")

    # When user arrives at buyThis page
    symbol = request.args.get("symbol")
    stock = lookup(symbol)
    return render_template("buyThis.html", stock=stock)


@app.route("/sellAll", methods=["POST"])
@login_required
def sellAll():
    """Sell all specified stock"""

    # Check if lookup is successful
    if lookup(request.form.get("symbol")) == None:
        return apology("invalid symbol", 400)

    # select all the shares currently owned
    symbol = request.form.get("symbol")
    user_id = session["user_id"]
    shares = db.execute("SELECT shares FROM stocks_owned WHERE user_id = ? AND symbol = ?", user_id, symbol)[0]["shares"]

    # delete data in stocks_owned table
    db.execute("DELETE FROM stocks_owned WHERE symbol = ? AND user_id = ?", symbol, user_id)

    # Update cash of user
    stock = lookup(symbol)
    name = stock["name"]
    price = stock["price"]
    cash = float((db.execute("SELECT * FROM users WHERE id = ?", user_id))[0]["cash"])
    gain = price * shares
    cash = cash + gain

    # Add cash after selling shares
    db.execute("UPDATE users SET cash = ?", cash)


    now = datetime.now(timezone("Hongkong"))
    # Update the transactions table
    db.execute("INSERT INTO transactions (user_id, symbol, shares, price, timestamp, type) VALUES(?, ?, ?, ?, ?, ?)", user_id, symbol, shares, price, now, "SELL")

    # Display message
    name = stock["name"]
    message = f"You have sold {shares} shares of {name} at {usd(price)} per share and gained {usd(gain)}"
    flash(message)

    return redirect("/")
