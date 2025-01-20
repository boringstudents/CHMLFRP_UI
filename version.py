from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return '1.5.2'

@app.route('/api/version')
def version():
    return jsonify({'version': '1.5.2'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
