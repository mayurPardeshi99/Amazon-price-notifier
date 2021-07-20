
# Amazon Price Drop Notifier

This is a web based application which is made in flask, which tracks prices for products on Amazon. User must sign up to use it. After signing up user can create their list products list just by adding Amazon product URL and their price range. User's added products price will update daily and an email will be sent to the user when the price is within the user budget.
This web application  website also contains an API to collect products details of users such as url, and their budget for daily checks from outside.


## Dependencies

1. flask

```bash
  pip install Flask
```
2. flask_sqlalchemy
```bash
  pip install Flask-SQLAlchemy
```
3. werkzeug.security
```bash
  pip install Werkzeug
```
4. flask_login
```bash
  pip install Flask-Login
```
5. itsdangerous
```bash
  pip install itsdangerous
```
6. flask_mail
```bash
  pip install Flask-Mail
```
7. dotenv
```bash
  pip install dotenv
```


  
## Installation

```bash
  Clone the repository
  Install all dependencies
  Set up environment variables
  Run main.py
```
    