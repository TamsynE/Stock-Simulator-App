import random
import datetime
from datetime import datetime, timedelta
from redis import Redis
from rq_scheduler import Scheduler
from flask import Blueprint, app, jsonify, request, session
import yfinance as yf
from ..db import get_db
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from app import scheduler  # Import directly from app/__init__.py
from flask import current_app
import pytz


# Create a Flask blueprint for stock-related routes
transaction_bp = Blueprint('transaction', __name__)

# API route to buy stocks


@transaction_bp.route('/buy', methods=['POST'])
def buy():
    data = request.get_json()
    ticker = data.get("ticker")
    numShares = int(data.get("numShares"))
    session['username'] = data.get("username")
    stock = yf.Ticker(ticker)
    stock_info = stock.info

    # Get the current stock price
    current_price = stock_info.get("currentPrice", 0)

    # Debug: Print stock price
    print(f"Buying {ticker}, {numShares} shares at ${current_price}")

    # Check if the stock price is valid
    if current_price <= 0:
        return jsonify({"error": "Invalid stock price"}), 400

    totalCost = numShares * current_price

    db_conn = get_db()
    id = db_conn.execute(
        "SELECT id FROM user WHERE username = ?", (session['username'],)).fetchone()
    cash = db_conn.execute(
        "SELECT totalCash FROM user WHERE username = ?", (session['username'],)).fetchone()

    # Debug: Print user info and cash available
    print(f"User ID: {id}, Cash Available: ${cash['totalCash']}")

    if cash is None or id is None:
        return jsonify({"error": "User not found"}), 404

    if totalCost <= cash['totalCash']:
        # Update user's total cash
        db_conn.execute("UPDATE user SET totalCash = totalCash - ? WHERE username = ?",
                        (totalCost, session['username']))

        # Log the buying action
        print("loading event log!!!")
        newCash = cash['totalCash'] - totalCost
        print(cash['totalCash'])
        db_conn.execute("INSERT INTO eventLog (id, totalCash, eventName, stockBought) VALUES (?, ?, ?, ?)",
                        (id['id'], newCash, 'Bought', ticker))
        print("--------------------------")

        # Check if the stock already exists in the portfolio
        existing_stock = db_conn.execute(
            "SELECT numShares, purchasePrice FROM portfolio WHERE ticker = ? AND id = ?",
            (ticker, id['id'])).fetchone()

        # Debug: Check if the stock already exists
        print(f"Existing stock: {existing_stock}")

        if existing_stock is None:
            # Insert the stock into the portfolio for the first time
            db_conn.execute(
                "INSERT INTO portfolio (ticker, numShares, id, purchasePrice) VALUES (?, ?, ?, ?)",
                (ticker, numShares, id['id'], current_price))
        else:
            # Update the number of shares if the stock already exists
            db_conn.execute(
                "UPDATE portfolio SET numShares = numShares + ? WHERE ticker = ? AND id = ?",
                (numShares, ticker, id['id']))

        db_conn.commit()
        return jsonify({"message": "Stock bought successfully", "totalCost": totalCost}), 200
    else:
        return jsonify({"error": "Insufficient funds"}), 400

# API route to sell stocks


@transaction_bp.route('/sell', methods=['POST'])
def sell():
    data = request.get_json()
    ticker = data.get("ticker")
    numShares = int(data.get("numShares"))
    session['username'] = data.get("username")
    stock = yf.Ticker(ticker)
    stock_info = stock.info
    currentPrice = stock_info.get("currentPrice", 0)

    db_conn = get_db()
    # Get user ID
    id = db_conn.execute(
        "SELECT id FROM user WHERE username = ?", (session['username'],)).fetchone()

    if id is None:
        return jsonify({"error": "User not found"}), 404

    # Get the current shares and purchase price from the portfolio
    currentShares = db_conn.execute(
        "SELECT numShares, purchasePrice FROM portfolio WHERE id = ? AND ticker = ?", (id['id'], ticker)).fetchone()

    if currentShares is None:
        return jsonify({"error": "No shares found in portfolio"}), 404

    # Ensure that the user has enough shares to sell
    if currentShares['numShares'] >= numShares:
        # Calculate the total profit for the shares being sold
        totalProfit = 0
        for _ in range(numShares):
            # Profit for each share sold = current price - purchase price
            totalProfit += (currentPrice - currentShares['purchasePrice'])

        # Update the user's cash balance
        db_conn.execute(
            "UPDATE user SET totalCash = totalCash + ? WHERE id = ?", (totalProfit, id['id']))
        cash = db_conn.execute(
            "SELECT totalCash FROM user WHERE username = ?", (session['username'],)).fetchone()
        # Log the selling action
        db_conn.execute(
            "INSERT INTO eventLog (id, totalCash, eventName, stockSold) VALUES (?, ?, ?, ?)", (id['id'], cash['totalCash'], 'Sold', ticker))

        # Update the portfolio by reducing the shares
        db_conn.execute(
            "UPDATE portfolio SET numShares = numShares - ? WHERE id = ? AND ticker = ?", (numShares, id['id'], ticker))

        # If all shares are sold, remove the ticker from the portfolio
        if currentShares['numShares'] - numShares == 0:
            db_conn.execute(
                "DELETE FROM portfolio WHERE id = ? AND ticker = ?", (id['id'], ticker))

        db_conn.commit()
        return jsonify({"message": "Stock sold successfully", "totalProfit": totalProfit}), 200
    else:
        return jsonify({"error": "Not enough shares to sell"}), 400


@transaction_bp.route('/portfolio', methods=['GET'])
def get_portfolio():
    username = session.get('username')
    if not username:
        return jsonify({"error": "User not logged in"}), 401

    db_conn = get_db()
    user_id = db_conn.execute(
        "SELECT id FROM user WHERE username = ?", (username,)).fetchone()

    if not user_id:
        return jsonify({"error": "User not found"}), 404

    portfolio = db_conn.execute(
        "SELECT ticker, purchasePrice, numShares FROM portfolio WHERE id = ?", (user_id['id'],)).fetchall()

    response_data = []
    for stock in portfolio:
        ticker = stock['ticker']
        numShares = stock['numShares']
        stock_info = yf.Ticker(ticker).info
        current_price = stock_info.get("currentPrice", 0)
        print(f"current Price: {current_price}")
        previous_close = stock_info.get("regularMarketPreviousClose", 0)
        purchase_price = stock['purchasePrice']
        print(f"purchase Price: {purchase_price}")
        price_change = current_price - purchase_price
        if previous_close:
            price_change_percent = (price_change / purchase_price) * 100
        else:
            price_change_percent = 0  # Default or flag for first purchase

        response_data.append({
            "ticker": ticker,
            "numShares": numShares,
            "currentPrice": current_price,
            "purchasePrice": purchase_price,
            "price_change": price_change,
            "price_change_percent": price_change_percent,
            "isInitialPurchase": previous_close == 0
        })

    return jsonify(response_data), 200


@transaction_bp.route('/schedule_buy', methods=['POST'])
def schedule_buy():
    data = request.get_json()
    ticker = data.get("ticker")
    numShares = int(data.get("numShares"))
    username = data.get("username")
    schedule_time = data.get("scheduleTime")
    schedule_datetime = datetime.strptime(schedule_time, "%Y-%m-%dT%H:%M")

    try:
        scheduler.add_job(
            func=buy,
            trigger="date",
            run_date=schedule_datetime,
            kwargs={'app': current_app._get_current_object(
            ), 'ticker': ticker, 'numShares': numShares, 'username': username},
            id=f"{username}-{ticker}-{schedule_time}",
            replace_existing=True
        )
        print(f"Job scheduled: {username}-{ticker} at {schedule_time}")

        return jsonify({"message": "Stock buy scheduled successfully", "schedule_time": schedule_time}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def buy(app, ticker, numShares, username):
    with app.app_context():
        try:
            print(f"Executing buy job: {ticker}, {numShares}, {username}")
            stock = yf.Ticker(ticker)
            stock_info = stock.info

            purchasePrice = stock_info.get("currentPrice", 0)
            totalCost = numShares * stock_info.get("currentPrice", 0)
            db_conn = get_db()
            id = db_conn.execute(
                "SELECT id FROM user WHERE username = ?", (username,)).fetchone()
            cash = db_conn.execute(
                "SELECT totalCash FROM user WHERE username = ?", (username,)).fetchone()

            if cash is None or id is None:
                print("User not found")
                return {"error": "User not found"}

            if totalCost <= cash['totalCash']:
                # Update user's total cash
                db_conn.execute("UPDATE user SET totalCash = totalCash - ? WHERE username = ?",
                                (totalCost, username))
                # Log the buying action
                newCash = cash['totalCash'] - totalCost
                db_conn.execute("INSERT INTO eventLog (id, totalCash, eventName, stockBought) VALUES (?, ?, ?, ?)",
                                (id['id'], newCash, 'Bought', ticker))
                # Insert stocks into portfolio
                db_conn.execute(
                    "INSERT INTO portfolio (ticker, purchasePrice, numShares, id) VALUES (?, ?, ?, ?) ON CONFLICT (ticker, id) DO UPDATE SET numShares = numShares + ?",
                    (ticker, purchasePrice, numShares, id['id'], numShares))
                db_conn.commit()
                print(f"Stock bought successfully: {ticker} by {username}")
                return {"message": "Stock bought successfully", "totalCost": totalCost}
            else:
                print("Insufficient funds")
                return {"error": "Insufficient funds"}
        except Exception as e:
            print(f"Error in scheduled job: {str(e)}")


@transaction_bp.route('/schedule_sell', methods=['POST'])
def schedule_sell():
    data = request.get_json()
    ticker = data.get("ticker")
    numShares = int(data.get("numShares"))
    username = data.get("username")
    schedule_time = data.get("scheduleTime")

    scheduler.add_job(
        func=sell,
        trigger="date",
        run_date=schedule_time,
        kwargs={'app': current_app._get_current_object(
        ), 'ticker': ticker, 'numShares': numShares, 'username': username},
        id=f"{username}-{ticker}-{schedule_time}",
        replace_existing=True
    )
    print(f"Job scheduled: {username}-{ticker} at {schedule_time}")

    return jsonify({"message": f"Sell job scheduled for {schedule_time}"}), 200


def sell(app, ticker, numShares, username):
    with app.app_context():
        stock = yf.Ticker(ticker)
        stock_info = stock.info

        totalProfit = numShares * stock_info.get("currentPrice", 0)
        db_conn = get_db()
        id = db_conn.execute(
            "SELECT id FROM user WHERE username = ?", (username,)).fetchone()
        if id is None:
            return jsonify({"error": "User not found"}), 404

        currentShares = db_conn.execute(
            "SELECT numShares FROM portfolio WHERE id = ? AND ticker = ?", (id['id'], ticker)).fetchone()

        if currentShares is None:
            return jsonify({"error": "No shares found in portfolio"}), 404

        if currentShares['numShares'] >= numShares:
            # Update user's total cash
            db_conn.execute(
                "UPDATE user SET totalCash = totalCash + ? WHERE id = ?", (totalProfit, id['id']))
            # Log the selling action
            cash = db_conn.execute(
                "SELECT totalCash FROM user WHERE username = ?", (username,)).fetchone()
            db_conn.execute(
                "INSERT INTO eventLog (id, totalCash, eventName, stockBought) VALUES (?, ?, ?, ?)", (id['id'], cash, 'Sold', ticker))
            # Update shares in portfolio
            db_conn.execute(
                "UPDATE portfolio SET numShares = numShares - ? WHERE id = ? AND ticker = ?", (numShares, id['id'], ticker))
            db_conn.commit()
            return jsonify({"message": "Stock sold successfully", "totalProfit": totalProfit}), 200
        else:
            return jsonify({"error": "Not enough shares to sell"}), 400
