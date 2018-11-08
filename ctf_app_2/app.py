from flask import Flask, request, render_template, send_from_directory
from config import flag_file
from os import system

app = Flask(__name__)

message = "MAIN MESSAGE"
total = len(flag_file) #total flags
current = 0 #collected flags

def process_flag(flag_input):
    global current
    if flag_input in flag_file.keys():
        current = current+1
        system(flag_file[flag_input][1]) #run command
        return flag_file[flag_input][0] #return file name
    else:
        return 'wrong.txt'

@app.route('/', methods=['GET', 'POST'])
def flag_submit():
    global message
    global total
    global current
    if request.method == 'POST':
        #return message from the file
        with open('files/'+process_flag(request.form['flag']),'r') as file:
            message = file.read()
        return render_template('index.html',message=message,total=total,current=current)
    return render_template('index.html',message=message,total=total,current=current)

if __name__ == "__main__":
    app.run(host='0.0.0.0',port=8000)
