#http://docs.cuckoosandbox.org/en/latest/customization/processing/

from cuckoo.common.exceptions import CuckooProcessingError
from cuckoo.common.abstracts import Processing
import os, requests

import feature_extractor

class mlmd(Processing):

    def run(self):
        self.key = "mlmd"

        try:
            if os.path.exists(self.file_path):
                #extract PE data, send to MLMD server, set data=reply
                features = feature_extractor.get_features(self.file_path)
                res = requests.post("http://localhost:8080/ML",json=features)
                data = res.json()
        except SomethingFailed:
            raise CuckooProcessingError("Failed")

        return data
