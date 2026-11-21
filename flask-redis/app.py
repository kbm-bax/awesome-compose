import os

from flask import Flask
from redis import Redis

app = Flask(__name__)

with open(os.environ['REDIS_PASSWORD_FILE']) as password_file:
    redis_password = password_file.read().strip()

redis = Redis(host='redis', port=6379, password=redis_password)

@app.route('/')
def hello():
    redis.incr('hits')
    counter = str(redis.get('hits'),'utf-8')
    return "This webpage has been viewed "+counter+" time(s)"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
