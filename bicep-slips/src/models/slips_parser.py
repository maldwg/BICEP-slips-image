from src.utils.models.ids_base import IDSParser, Alert
import json 
import os 
import os.path
from datetime import datetime
import re

class SlipsParser(IDSParser):
    # TODO 10: go voer all log files instead of the main one if existing
    alert_file_location = "/opt/logs/alerts.json"
    alert_file_location_with_correct_timestamps = "/opt/logs/alerts.log"

    async def parse_alerts(self, file_location=alert_file_location):
        
        parsed_lines = []
        line_counter = 0
    
        if not os.path.isfile(file_location) or not os.path.isfile(self.alert_file_location_with_correct_timestamps):
            return parsed_lines

        timestamp_file = open(self.alert_file_location_with_correct_timestamps)
        timestamp_file_content = timestamp_file.readlines()
        with open(file_location, "r") as alerts:
            for line in alerts:
                line_as_json = json.loads(line)
                timestamp_file_line = timestamp_file_content[line_counter]
                timestamp = datetime.fromisoformat(timestamp_file_line.split(" ")[0]).replace(tzinfo=None)
                parsed_lines.append(await self.parse_line(line_as_json, timestamp))
                line_counter += 1

        # remove file to prevent double sending results after next execution
        timestamp_file.close()
        # erase files content but do not delete the file itself
        open(file_location, 'w').close()
        open(self.alert_file_location_with_correct_timestamps, 'w').close()

        return parsed_lines
    
    async def parse_line(self, line, timestamp):
        parsed_line = Alert()
        # todo: check if Is detect time now correctt in slips? --> it is not --> check if necessaray and use other tehniques
        parsed_line.time = str(timestamp)
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
        parsed_line.severity = await self.normalize_threat_levels(await self.get_threat_level(line))

        return parsed_line
    
    async def normalize_threat_levels(self, threat: int):
        # threat levels are from 0 (info) to 4 (critical)
        # parse the levels into numbers
        max_level = 4
        return round(threat / max_level,2)

    async def get_threat_level(self, line: str, ):
        print(line)
        # get everything after substring for threat level
        try:
            regex_result = re.search(r'threat level: (\w+)', line.get("Attach")[0].get("Content"))
            match = regex_result.group(1)
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
        # As alert lines will not have this info but rather a normal threat_level, use that instead
        except Exception as e:
            try:
                threat_level = line.get("threat_level")
                # TODO 8: how to scale the threat level correctly??
                return int(threat_level)
            except Exception as e:
                print(f"Could not determine threat level for line {line}")
                raise e


        
