from  src.utils.models.ids_base import IDSBase
from fastapi import UploadFile
import shutil

class Slips(IDSBase):
    configuration_location = "/tmp/slips.yaml"

    def configure(self, temporary_file):
        shutil.move(temporary_file, self.configuration_location)
        return "succesfuly configured"
    
    def configure_ruleset(self, temporary_file):
        return "No ruleset to patch"
