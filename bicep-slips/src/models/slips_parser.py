from src.utils.models.ids_base import IDSParser, Alert
import json 
import os 
from datetime import datetime

class SlipsParser(IDSParser):
    
    alertFileLocation = ""
    async def parse_alerts_from_network_traffic(self, file_location=alertFileLocation):
        
        parsed_lines = []

        with open(file_location, "r") as file:
            for line in file:
                line_as_json = json.loads(line)
                parsed_lines.append(self.parse_line(line_as_json))

        # remove file to prevent double sending results after next execution
        os.remove(file_location)
    
        return parsed_lines
    
    # TODO 11: Either refactor so that only one parse mtehod exists (botha re equivalent) or identify things that the modes seperate from each other
    async def parse_alerts_from_network_traffic(self, file_location=alertFileLocation):
        parsed_lines = []

        with open(file_location, "r") as file:
            for line in file:
                line_as_json = json.loads(line)
                parsed_lines.append(self.parse_line(line_as_json))

        # remove file to prevent double sending results after next execution
        os.remove(file_location)
    
        return parsed_lines
    async def parse_line(self, line):
        parsed_line = Alert()
        # todo: check if Is detect time now correctt in slips? --> it is not --> check if necessaray and use other tehniques
        parsed_line.time = datetime.strptime(line.get("DetectTime"), self.timestamp_format) 
        # since it is an array, acces the first element, then get the ip, the result is also in an array
        parsed_line.source = line.get("Source")[0].get("IP4")[0]
        try:
            parsed_line.destination = line.get("Target")[0].get("IP4")[0]
        except TypeError as e:
            # many time there is no target, hence leave the information empty then
            parsed_line.destination = ""
        parsed_line.message = line.get("Attach")[0].get("Content")
        parsed_line.type = line.get("Category")[0]
        # TODO 6: find out scale and adapt to it  --> from 0 to 1 or 0 to 10 ??
        parsed_line.severity = line.get("accumulated_threat_level")

        return parsed_line