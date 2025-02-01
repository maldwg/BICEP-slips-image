import asyncio
from  src.utils.models.ids_base import IDSBase
import shutil
import os
from src.utils.general_utilities import execute_command
from .slips_parser import SlipsParser

class Slips(IDSBase):
    configuration_location: str = "/tmp/slips.yaml"
    # the interface to listen on in network analysis modes
    log_location: str = "/opt/logs"

    # unqiue variables
    working_dir = "/StratosphereLinuxIPS"
    parser = SlipsParser()


    async def configure(self, temporary_file):
        shutil.move(temporary_file, self.configuration_location)
        try:
            os.mkdir(self.log_location)
            return "succesfully configured"
        except Exception as e:
            print(e)
            return e
    
    # method needs to be implemented,even if it does nothing
    async def configure_ruleset(self, temporary_file):
        pass
    
    async def execute_network_analysis_command(self):
        os.chdir(self.working_dir)
        start_slips = ["./slips.py", "-c", self.configuration_location, "-i", self.tap_interface_name, "-o", self.log_location]
        pid = await execute_command(start_slips)
        return pid

    async def execute_static_analysis_command(self, file_path):
        os.chdir(self.working_dir)
        command = ["./slips.py", "-c", self.configuration_location, "-f", file_path, "-o", self.log_location]
        pid = await execute_command(command)
        return pid