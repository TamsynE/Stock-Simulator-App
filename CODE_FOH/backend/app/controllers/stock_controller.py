import os
from flask import Blueprint, jsonify, request
import yfinance as yf
import pandas as pd

stock_bp = Blueprint('stock', __name__)


@stock_bp.route('/stocklist', methods=['GET'])
def get_stocks():
    stocks = {}
    tickers_file_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "logs", "tickers.txt"
    )

    with open(tickers_file_path, "r") as file:
        tickers = [line.strip() for line in file.readlines()]

    for ticker in tickers[:5]:
        stock = yf.Ticker(ticker)
        stock_info = stock.info
        stocks[ticker] = {
            "name": stock_info.get("shortName"),
            "price": stock_info.get("currentPrice"),
        }

    return jsonify(stocks)


@stock_bp.route('/stockSearch', methods=['POST'])
def searchStock():
    searched_stock = None

    if request.method == "POST":
        data = request.get_json()
        search_ticker = data.get("stock_search").upper()
        stock = yf.Ticker(search_ticker)
        stock_info = stock.info

        if "shortName" in stock_info and "currentPrice" in stock_info:
            searched_stock = {
                "ticker": search_ticker,
                "name": stock_info["shortName"],
                "price": stock_info["currentPrice"],
            }

            # Get historical data for the last 5 days
            hist = stock.history(period="30d")

            # Convert the index (Timestamps) to strings and format the historical prices
            history_data = hist['Close'].to_dict()
            history_data = {str(date.date()): price for date,
                            price in history_data.items()}

            return jsonify({
                "stock": searched_stock,
                "history": history_data  # Use the modified history data
            })

        return jsonify({"error": "Stock not found or data unavailable."}), 404

    return jsonify({"error": "Invalid request."}), 400
