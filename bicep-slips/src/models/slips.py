import asyncio
from  src.utils.models.ids_base import IDSBase
import shutil
import os
from src.utils.general_utilities import create_and_activate_network_interface,remove_network_interface,mirror_network_traffic_to_interface,execute_command, wait_for_process_completion
from src.utils.fastapi.utils import send_alerts_to_core, send_alerts_to_core_periodically
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
        self.tap_interface_name = f"tap{self.container_id}"

        try:
            os.mkdir(self.log_location)
            return "succesfully configured"
        except Exception as e:
            print(e)
            return e
    
    async def configure_ruleset(self, temporary_file):
        return "No ruleset to patch"
    
    async def startNetworkAnalysis(self):
        await create_and_activate_network_interface(self.tap_interface_name)
        pid = await mirror_network_traffic_to_interface(default_interface="eth0", tap_interface=self.tap_interface_name)
        self.pids.append(pid)
        os.chdir(self.working_dir)
        start_slips = ["./slips.py", "-c", self.configuration_location, "-i", self.tap_interface_name, "-o", self.log_location]
        pid = await execute_command(start_slips)
        self.pids.append(pid)

        self.send_alerts_periodically_task = asyncio.create_task(send_alerts_to_core_periodically(ids=self))
        print("task:")
        print(self.send_alerts_periodically_task)
        
        return f"started network analysis for container with {self.container_id}"


    async def startStaticAnalysis(self, file_path):
        os.chdir(self.working_dir)
        command = ["./slips.py", "-c", self.configuration_location, "-f", file_path, "-o", self.log_location]
        pid = await execute_command(command)
        self.pids.append(pid)
        await wait_for_process_completion(pid)
        self.pids.remove(pid)
        # if analysis has not been cancled while running
        if self.static_analysis_running:
            await send_alerts_to_core(ids=self)
        await self.stopAnalysis()            

    # overrides the default method
    async def stopAnalysis(self):
        from src.utils.fastapi.utils import tell_core_analysis_has_finished

        self.static_analysis_running = False
        await self.stop_all_processes()
        if self.send_alerts_periodically_task != None:            
            print(self.send_alerts_periodically_task)
            if not self.send_alerts_periodically_task.done():
                self.send_alerts_periodically_task.cancel()
            self.send_alerts_periodically_task = None
        if self.tap_interface_name != None:
            await remove_network_interface(self.tap_interface_name)
        await tell_core_analysis_has_finished(self)