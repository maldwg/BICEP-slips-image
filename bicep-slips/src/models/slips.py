from  src.utils.models.ids_base import IDSBase
from fastapi import UploadFile
from src.utils.fastapi.routes import tell_core_analysis_has_finished
import shutil

class Slips(IDSBase):
    configuration_location: str = "/tmp/slips.yaml"
    container_id: int = None

    def configure(self, temporary_file):
        shutil.move(temporary_file, self.configuration_location)
        return "succesfuly configured"
    
    def configure_ruleset(self, temporary_file):
        return "No ruleset to patch"
    
    async def startNetworkAnalysis(self):
        return "Started Network analysis"
    
    async def startStaticAnalysis(self, file_path, container_id):
        self.container_id = container_id
        return "Started Static Analysis"
    
    async def stopAnalysis(self):
        await tell_core_analysis_has_finished(container_id=self.container_id)
        return "Stopped analysis"
