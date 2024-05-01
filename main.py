import time
from random import randint

from flask import Flask, render_template, request

app = Flask(__name__)
k = 0


@app.route('/')
def start():
    return render_template('start.html')


@app.route('/kluet', methods=["GET", "POST"])
def kluet():
    if request.method == "POST":
        time.sleep(randint(1, 10))
        return render_template("kluet.html")


@app.route('/process', methods=["GET", "POST"])
def process():
    global k
    k += 1
    return render_template("process.html", k=k)


@app.route('/poimal', methods=["GET", "POST"])
def poimal():
    return render_template("poimal.html")


@app.route('/itog', methods=["GET", "POST"])
def fish():
    k = randint(0, 9)
    jpg = ['amur.jpg', 'forel.jpg', 'gorbusha.jpg', 'karas.jpg', 'karp.jpg', 'lesch.jpg', 'lin.jpg', 'okun.jpg',
           'sudak.jpg', 'yaz.jpg']
    return render_template("fish.html", picture=jpg[k])


@app.route('/vozvrat', methods=["GET", "POST"])
def vozvrat():
    return render_template("start.html")


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')
