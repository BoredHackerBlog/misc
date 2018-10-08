#Import Web related things
from flask import Flask, request, Response, render_template, jsonify
import json, hashlib
from functools import wraps
app = Flask(__name__)

#Import Machine Learning related things
import numpy as np
from sklearn import preprocessing, neighbors, tree, ensemble, svm
from sklearn.model_selection import cross_val_score
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

#Read features and do Machine Learning
MLfile = "./dataset/ben_backdoor.csv" #change this as needed
df = pd.read_csv(MLfile)
df.replace('?',-99999, inplace=True)

header1 = list(df.columns.values)
header2 = list(df.keys())

X = np.array(df.drop(['label'],1))
y = np.array(df['label'])

#Do training here
dec_clf = tree.DecisionTreeClassifier()
dec_clf.fit(X, y)

knn_clf = neighbors.KNeighborsClassifier()
knn_clf.fit(X, y)

forest_clf = ensemble.RandomForestClassifier()
forest_clf.fit(X, y)

svm_clf = svm.SVC()
svm_clf.fit(X, y)

#Classify the file based on Features
def MLClassify(features):
    return_data = {}
    #Do predication and add output to return_data, it 0 or something else
    return_data["dec_clf"] = dec_clf.predict([features])[0]
    return_data["knn_clf"] = knn_clf.predict([features])[0]
    return_data["forest_clf"] = forest_clf.predict([features])[0]
    return_data["svm_clf"] = svm_clf.predict([features])[0]

    #we're relying on forest_clf algo for Benign or Malware results
    classification = return_data["forest_clf"]

    #I used the label 0 for benign throughout the datasets.
    #for malware label, i used 1,2,3,4
    if classification == 0:
        return_data["Forest Classification"] = "Benign"
    else:
        return_data["Forest Classification"] = "Malware"

    return json.loads(json.dumps(return_data))

#Proces requests
#Usage:
#features = feature_extractor.get_features(file_path)
#res = requests.post('http://localhost:8080/ML',json=features)
#res.json()
#results are in json format and include information from different algorithms
@app.route("/ML", methods=["POST"])
def ML():
    try:
        if request.json:
            results = MLClassify((request.json).values())
            return jsonify(results)
        else:
            return "Something failed!"

    except:
        return "Something failed!"

if __name__ == "__main__":
    app.debug = True
    app.run(host="0.0.0.0", port=8080)

