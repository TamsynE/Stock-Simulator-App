# FOH_PSE
FOH allows users to trade, sell, and adjust stocks whilst managing and viewing their own stock portfolio. FOH will simulate a stock trading platform whilst implementing multi-user login and an administration account.

# Github
https://github.com/ettany/FOH_PSE

# Team Members & Roles
Manila Aryal: Activity Log & Password Hashing Lead

Grace Frizzell: Database & Transaction Lead

Tamsyn Evezard: Authentication & API Lead

Ngoc Bui: Visualization & CAPTCHA Lead

Berkan Guven: Facial Recognition Lead

## Accomplished Work
- Username and password authentication for users and admin that maintains session (functionality included in the register, login, and logout pages)​

- Password hashing, CAPTCHA and optional face recognition login for account security​

- Working database with user, portfolio, and eventLog tables​

- Separate administration dashboard with privileges for creating and deleting user accounts

- <b>Portfolio page ​</b>

    - displays user balance and stock portfolio

    - graph of profit
 
    <img width="500" alt="image" src="https://github.com/user-attachments/assets/23a67ab7-949f-4f85-b07e-39de830b3794">


- <b>Trade page </b>

  - displaying updated stock prices for 5 stocks with a table and graph​

  - ability to search for a specific stock and display its details​

  - ability to buy, sell, or adjust stock​s

  - graph of searched stock's performance over the last 30 days

    <img width="500" alt="image" src="https://github.com/user-attachments/assets/6ad5f019-9578-44bd-90f1-19cce35e7d58">


- <b>Log page​ </b>

    - table log of activities with details for: buy, sell, scheduled buy/sell, logging on, logging out
  
 
     <img width="500" alt="image" src="https://github.com/user-attachments/assets/9ba34ec8-1c27-4211-a442-a97ee9137d05">

 
# Developing the product to ensure compatibility:​

Python (3.10.15) & Flask (backend)​

SQL (database schema)​

Frontend (HTML, CSS, JavaScript)​

API: yahoo finance
## Install dependencies

See requirements.txt files in frontend and backend for libraries and dependencies


## Running backend
export FLASK_APP=backend/app

flask init-db

flask --app backend/server.py run

## Running frontend
python frontend/interface.py

## FINAL DEMO
https://www.youtube.com/watch?v=7XaVBbRt8u4 
