from flask import Flask, request, render_template, send_from_directory
from config import flag_file

app = Flask(__name__)

def process_flag(flag_input):
    if flag_input in flag_file.keys():
        return flag_file[flag_input]
    else:
        return 'wrong.txt'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/flag', methods=['GET', 'POST'])
def flag_submit():
    if request.method == 'POST':
        return send_from_directory(directory='files',filename=(process_flag(request.form['flag'])))
    return '''
<html>
        <body bgcolor=lightblue>
        <center>
        <h2>Enter your flag here:</h2>
        <h3>Format: ctf{flag}</h3>
        <form method="post">
            <p><input style="height:50px; width:500px; font-size: 16px" type=text name=flag></p>
            <input style="height:50px; width:100px; font-size: 16px" type="submit" value="Submit">
        </form>
        </center>
        </body>
</html>
'''

if __name__ == "__main__":
    app.run(host='0.0.0.0',port=8000)
