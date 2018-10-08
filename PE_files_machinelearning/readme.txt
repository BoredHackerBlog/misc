Install Python 2.7, if not installed already. Install python-pip as well.
Execute "pip -r requirements.txt" to install libraries required to run the python scripts.

dataset folder contains dataset for machine learning. 
feature_extractor.py is a script that can be imported into other applications and be used to extract features
ml_server.py Extracted features can be sent to ml_server.py via an API call and ml_server will reply with machine learning analysis results

ml_server.py loads data from dataset folder.
feature_extractor can be used to extract features of an EXE file and those features can be sent to ml_server for analysis.



catch_pe.py monitors files.log (file created by broIDS which keeps track of extracted files)
When an EXE file/PE file is extracted by BroIDS, it's logged to files.log with metadata.
catch_pe.py looks for PE file extraction in files.log and checks if the file is really an exe file.
If the file is an exe file then catch_pe.py will use feature_extractor to get features and send them to mlmd server (ml_server.py)
if mlmd server replies with machine learning results.
User is alerted by printout of the machine learning information and metadata on the command line.

