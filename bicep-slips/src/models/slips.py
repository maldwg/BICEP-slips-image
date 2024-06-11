from  src.utils.models.ids_base import IDSBase
from fastapi import UploadFile
from src.utils.fastapi.routes import tell_core_analysis_has_finished
import shutil
import os
from src.utils.fastapi.utils import stop_process, execute_command, wait_for_process_completion

class Slips(IDSBase):
    configuration_location: str = "/tmp/slips.conf"
    container_id: int = None
    pid: int = None
    working_dir = "/StratosphereLinuxIPS"

    async def configure(self, temporary_file):
        shutil.move(temporary_file, self.configuration_location)
        return "succesfuly configured"
    
    async def configure_ruleset(self, temporary_file):
        return "No ruleset to patch"
    
    async def startNetworkAnalysis(self):
        return "Started Network analysis"
    
    async def startStaticAnalysis(self, file_path, container_id):
        self.container_id = container_id
        os.chdir(self.working_dir)
        command = ["./slips.py", "-c", self.configuration_location, "-f", file_path]
        pid = await execute_command(command)
        self.pid = pid
        await wait_for_process_completion(pid)
        await self.stopAnalysis()            
    

    
    async def stopAnalysis(self):
        await stop_process(self.pid)
        self.pid = None
        await tell_core_analysis_has_finished(container_id=self.container_id)


    
