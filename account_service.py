import sqlite3


# It is important that the get_balance function only returns the balance if the owner
# is the same as the one in the database. This is to prevent unauthorized viewing of
# account balances.

# Whenever we have to deal with user input and a database, we always have to be
# careful about SQL injection. This is why we use parameterized queries. Parameterized queries
# ensure that the SQL query will be executed exacly as it is written, and that
# the user input will not be executed as part of the SQL query.
def get_balance(account_number, owner):
    """
    Retrieve the balance for a specific account and owner from the database.

    Args:
        account_number (int or str): The unique identifier of the account.
        owner (str): The name or identifier of the account owner.

    Returns:
        float or None: The account balance if the account exists and belongs to the owner, 
        otherwise None.
    """
    try:
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        cur.execute('''
            SELECT balance FROM accounts where id=? and owner=?''',
            (account_number, owner))
        row = cur.fetchone()
        if row is None:
            return None
        return row[0]
    finally:
        con.close()

# Again here we prevent the possibility of SQL injection by using parameterized queries.
def do_transfer(source, target, amount):
    """
    Transfer a specified amount from the source account to the target account.

    Args:
        source (int or str): The unique identifier of the source account.
        target (int or str): The unique identifier of the target account.
        amount (float): The amount of money to transfer.

    Returns:
        bool: True if the transfer was successful (i.e., the target account exists
        and the update was performed), False otherwise.
    """
    try:
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        cur.execute('''
            SELECT id FROM accounts where id=?''',
            (target,))
        row = cur.fetchone()
        if row is None:
            return False
        cur.execute('''
            UPDATE accounts SET balance=balance-? where id=?''',
            (amount, source))
        cur.execute('''
            UPDATE accounts SET balance=balance+? where id=?''',
            (amount, target))
        con.commit()
        return True
    finally:
        con.close()
