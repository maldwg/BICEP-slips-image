import asyncio
from  src.utils.models.ids_base import Alert, IDSBase
from fastapi import UploadFile
import shutil
import os
from src.utils.fastapi.utils import execute_command, wait_for_process_completion
from .slips_parser import SlipsParser

class Slips(IDSBase):
    configuration_location: str = "/tmp/slips.conf"
    pid: int = None
    send_alerts_task = None
    # the interface to listen on in network analysis modes
    network_interface = "eth0"
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
    
    async def configure_ruleset(self, temporary_file):
        return "No ruleset to patch"
    
    async def startNetworkAnalysis(self):
        # set network adapter to promiscuous mode
        command = ["ip", "link", "set", self.network_interface, "promisc", "on"]
        await execute_command(command)

        os.chdir(self.working_dir)
        command = ["./slips.py", "-c", self.configuration_location, "-i", self.network_interface, "-o", self.log_location]
        pid = await execute_command(command)
        self.pid = pid

        self.send_alerts_task = asyncio.create_task(self.parser.parse_alerts_from_network_traffic())
        
        return f"started network analysis for container with {self.container_id}"


    async def startStaticAnalysis(self, file_path):
        from src.utils.fastapi.routes import send_alerts_to_core
        os.chdir(self.working_dir)
        command = ["./slips.py", "-c", self.configuration_location, "-f", file_path]
        pid = await execute_command(command)
        self.pid = pid
        await wait_for_process_completion(pid)
        alerts: list[Alert] = await self.parser.parse_alerts_from_file()
        await send_alerts_to_core(ids=self, alerts=alerts, analysis_type="static")
        await self.stopAnalysis()            

    # overrides the default method
    # TODO: multiple threads need to be closed
    async def stopAnalysis(self):
        from src.utils.fastapi.utils import stop_process
        from src.utils.fastapi.routes import tell_core_analysis_has_finished

        await stop_process(self.pid)
        await self.send_alerts_task.cancel()
        self.pid = None
        return await tell_core_analysis_has_finished(self)