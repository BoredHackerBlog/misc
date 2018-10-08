cp ../catch_pe.py .
cp ../feature_extractor.py .
python catch_pe.py &
/usr/local/bro/bin/bro -r ../2_files_downloaded.pcapng ../extract-all-files.bro
