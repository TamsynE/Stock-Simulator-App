DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS portfolio;
DROP TABLE IF EXISTS eventLog;

CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(100) NOT NULL,
  totalCash DECIMAL(15,2) DEFAULT 100000,
  photo TEXT
);

CREATE TABLE portfolio (
    ticker VARCHAR(10) NOT NULL,
    numShares INTEGER,
    id INTEGER,
    purchasePrice DECIMAL(15, 2),
    FOREIGN KEY (id) REFERENCES user(id),
    UNIQUE (ticker, id)  -- This makes the combination of ticker and id unique
);


CREATE TABLE eventLog (
    id INTEGER,
    totalCash DECIMAL(15,2),
    eventName TEXT CHECK(eventName IN ('Bought', 'Sold', 'Logged on', 'Logged out')) NOT NULL,
    stockSold VARCHAR(10),
    stockBought VARCHAR(10),
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id) REFERENCES user(id),
    FOREIGN KEY(totalCash) REFERENCES user(totalCash)
);

