from src.utils.models.ids_base import IDSParser, Alert
import json 
import os 
from datetime import datetime
import re

class SlipsParser(IDSParser):
    
    alertFileLocation = ""
    async def parse_alerts_from_network_traffic(self, file_location=alertFileLocation):
        
        parsed_lines = []

        with open(file_location, "r") as file:
            for line in file:
                line_as_json = json.loads(line)
                parsed_lines.append(await self.parse_line(line_as_json))

        # remove file to prevent double sending results after next execution
        os.remove(file_location)
    
        return parsed_lines
    
    # TODO 11: Either refactor so that only one parse mtehod exists (botha re equivalent) or identify things that the modes seperate from each other
    async def parse_alerts_from_network_traffic(self, file_location=alertFileLocation):
        parsed_lines = []

        with open(file_location, "r") as file:
            for line in file:
                line_as_json = json.loads(line)
                parsed_lines.append(await self.parse_line(line_as_json))

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
        # parse the nested threat level to a number
        parsed_line.severity = await self.normalize_threat_levels(await self.get_threat_level(parsed_line.message))

        return parsed_line
    
    async def normalize_threat_levels(self, threat: int):
        # threat levels are from 0 (info) to 4 (critical)
        # parse the levels into numbers
        max_level = 4
        return round(threat / max_level,2)

    async def get_threat_level(self, content: str):
        # get everything after substring for threat level
        re = re.seach(r'threat level: (\w+)', content)
        match = re.group(1)

        if match == "info":
            return 0    
        elif match == "low":
            return 1
        elif match == "medium":
            return 2
        elif match == "high":
            return 3
        elif match == "critical":
            return 4 
        
