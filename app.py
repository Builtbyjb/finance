import os
import time
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

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


current_time = time.ctime()


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Gets user balance
    users = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = float(users[0]["cash"])

    # Get portfolio details
    portfolio = db.execute("SELECT * FROM buying WHERE user_id = ?", session["user_id"])

    # Get grand total
    total_list = []
    totals = db.execute("SELECT total FROM buying WHERE user_id = ?", session["user_id"])
    for t in totals:
        total_list.append(float(t["total"].removeprefix("$")))
    tots = sum(total_list)
    if tots is None:
        grand_total = 0 + cash
    else:
        grand_total = float(tots) + cash

    # Gets username for current user
    display_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    dis_name = display_name[0]["username"]

    return render_template("index.html", cash=usd(cash), total=usd(grand_total), portfolio=portfolio, display_name=dis_name)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Get user info
        symbol = request.form.get("symbol")
        stock_info = lookup(symbol)
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("shares nust be whole number")

        # Validate user input
        if not stock_info:
            return apology("invalid stock symbol")
        elif shares < 1:
            return apology("invalid share amount")

        # Gets total amount to buy
        total = shares * float(stock_info["price"])

        # Gets user balance
        users = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = float(users[0]["cash"])

        # Checks if the user as sufficient balance.
        if total > cash:
            return apology("insufficient funds")

        # Update buy_history
        db.execute("INSERT INTO buy_history(symbol, name, shares, price, total, time, user_id) VALUES(?, ?, ?, ?, ?, ?, ?)",
                   stock_info["symbol"], stock_info["name"], shares, usd(stock_info["price"]), usd(total), current_time, session["user_id"])

        # Get owned shares
        owned_shares = db.execute("SELECT shares FROM buying WHERE symbol = ?", stock_info["symbol"])
        if owned_shares:
            o_shares = int(owned_shares[0]["shares"])

        # Gets previous total
        prev_total = db.execute("SELECT total FROM buying WHERE symbol = ?", stock_info["symbol"])
        if prev_total:
            p_total = float(prev_total[0]["total"].removeprefix("$"))

        # Get owned stocks symbols:
        owned_stocks = []
        owned_stocks_symbols = db.execute("SELECT symbol FROM owned_stocks WHERE user_id = ?", session["user_id"])
        for own in owned_stocks_symbols:
            owned_stocks.append(own["symbol"])

        # Checks if the user as bought the type of stock in the past
        if stock_info["symbol"] in owned_stocks:
            db.execute("UPDATE buying SET shares = ? WHERE symbol = ?", (shares + o_shares), stock_info["symbol"])
            db.execute("UPDATE buying SET price = ? WHERE symbol = ?", usd(stock_info["price"]), stock_info["symbol"])
            db.execute("UPDATE buying SET total = ? WHERE symbol = ?", usd((total + p_total)), stock_info["symbol"])

        else:
            # Keep track of stock symbols
            db.execute("INSERT INTO owned_stocks(symbol, user_id) VALUES(?, ?)", stock_info["symbol"], session["user_id"])

            # Update buying table
            db.execute("INSERT INTO buying (symbol, name, shares, price, total, user_id) VALUES(?, ?, ?, ?, ?, ?)",
                       stock_info["symbol"], stock_info["name"], shares, usd(stock_info["price"]), usd(total), session["user_id"])

        # Update user balance
        new_balance = cash - total
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_balance, session["user_id"])

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Get buying history
    buy_history = db.execute("SELECT * FROM buy_history WHERE user_id = ?", session["user_id"])

    # Get selling history
    sell_history = db.execute("SELECT * FROM sell_history WHERE user_id = ?", session["user_id"])

    return render_template("history.html", buy_history=buy_history, sell_history=sell_history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

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
    if request.method == "POST":
        # Get user input
        symbol = request.form.get("symbol")
        symbols = lookup(symbol)

        if not symbols:
            return apology("invalid stock symbol")
        else:
            price = usd(symbols["price"])
            return render_template("quoted.html", symbols=symbols, price=price)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Get registration information
        username = request.form.get("username")
        password = request.form.get("password")
        password2 = request.form.get("confirmation")

        # Validate user input
        if not username or not password or not password2:
            return apology("input fields cannot be empty")
        elif password != password2:
            return apology("passwords do not match")

        # Checks for unique usernames
        u_username = []
        unique_username = db.execute("SELECT username FROM users")
        for u in unique_username:
            u_username.append(u["username"])

        if username in u_username:
            return apology("username already exist")
        else:
            # Generate hash password
            pwhash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

            # Stores registration information in the database
            db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", username, pwhash)

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # Get user information.
        symbol = request.form.get("symbol")
        stock_info = lookup(symbol)
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("shares nust be whole number")

        # Validate user input
        if not stock_info:
            return apology("invalid stock symbol")
        elif shares < 1:
            return apology("invalid share amount")

        # Gets owned shares
        owned_shares = db.execute("SELECT shares FROM buying WHERE symbol = ?", stock_info["symbol"])
        o_shares = int(owned_shares[0]["shares"])

        # checks if the user can afford the shares;
        if shares > o_shares:
            return apology("invalid amount of shares")

        # Gets total amount to sell
        total = shares * float(stock_info["price"])

        # Update sell_history
        db.execute("INSERT INTO sell_history(symbol, name, shares, price, total, time, user_id) VALUES(?, ?, ?, ?, ?, ?, ?)",
                   stock_info["symbol"], stock_info["name"], shares, usd(stock_info["price"]), usd(total), current_time, session["user_id"])

        # Gets user balance
        users = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = float(users[0]["cash"])

        # Gets previous total
        prev_total = db.execute("SELECT total FROM buying WHERE symbol = ?", stock_info["symbol"])
        p_total = float(prev_total[0]["total"].removeprefix("$"))

        # Update the buying table and portfolio.
        db.execute("UPDATE buying SET shares = ? WHERE symbol = ?", (o_shares - shares), stock_info["symbol"])

        # Checks if the value of shares is equal to zero.
        owned_shares = db.execute("SELECT shares FROM buying WHERE symbol = ?", stock_info["symbol"])
        o_shares = int(owned_shares[0]["shares"])

        if o_shares == 0:
            # Delete the stock from the buying table and owned_stocks table if the user as no shares left
            db.execute("DELETE FROM buying WHERE symbol = ?", stock_info["symbol"])
            db.execute("DELETE FROM owned_stocks WHERE symbol = ?", stock_info["symbol"])
        else:
            # If shares not equal to zero
            db.execute("UPDATE buying SET price = ? WHERE symbol = ?", usd(stock_info["price"]), stock_info["symbol"])
            db.execute("UPDATE buying SET total = ? WHERE symbol = ?", usd(p_total - total), stock_info["symbol"])

        # Update user balance
        new_balance = cash + total
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_balance, session["user_id"])

        return redirect("/")

    else:
        # Get owned stocks symbols:
        owned_stocks = []
        owned_stocks_symbols = db.execute("SELECT symbol FROM owned_stocks WHERE user_id = ?", session["user_id"])
        for own in owned_stocks_symbols:
            owned_stocks.append(own["symbol"])
        return render_template("sell.html", owned_stocks=owned_stocks)


@app.route("/deposit", methods=["POST"])
@login_required
def deposit():
    # Get user input
    try:
        deposit = int(request.form.get("deposit"))
    except ValueError:
        return apology("deposit must be a positive whole number")

    # Validate user input
    if not deposit:
        return apology("invalid deposit")
    elif deposit < 100:
        return apology("minimum deposit amount is $100")

    # Gets user balance
    users = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = float(users[0]["cash"])

    # Update user balance
    new_balance = cash + deposit
    db.execute("UPDATE users SET cash = ? WHERE id = ?", new_balance, session["user_id"])

    return redirect("/")


@app.route("/ch_pw", methods=["POST"])
@login_required
def ch_pw():
    chp = request.form.get("changepass")

    if chp:

        return render_template("changepass.html")


@app.route("/changepass", methods=["GET", "POST"])
@login_required
def changepass():
    if request.method == "POST":
        # Get user input
        current_pass = request.form.get("oldpassword")
        new_pass = request.form.get("newpassword")
        new_pass2 = request.form.get("confirmnew")

        # Validate user input
        if not current_pass or not new_pass or not new_pass2:
            return apology("Invalid Input")

        # Get current password from database
        current_db_pass = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])
        c_db_pass = current_db_pass[0]["hash"]

        # Checks if the current password is current
        if not check_password_hash(c_db_pass, current_pass):
            return apology("incorrect password")

        # Checks if the new password match.
        if new_pass != new_pass2:
            return apology("new passwords do not match")

        # Generate hash password
        new_pwhash = generate_password_hash(new_pass, method='pbkdf2:sha256', salt_length=8)

        # Update password
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_pwhash, session["user_id"])

        return redirect("/login")

    else:
        return render_template("changepass.html")