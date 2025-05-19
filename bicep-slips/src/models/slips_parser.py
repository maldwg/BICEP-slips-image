from src.utils.models.ids_base import IDSParser, Alert
import json 
import os 
import os.path
from datetime import datetime, timezone

class SlipsParser(IDSParser):
    alert_file_location = "/opt/logs/alerts.json"
    flows_as_hashmap = {}

    async def parse_alerts(self):
        parsed_lines = []   

        if not os.path.isfile(self.alert_file_location):
            return parsed_lines

        with open(self.alert_file_location, "r") as alerts:
            for line in alerts:
                try:
                    line_as_json = json.loads(line)
                    parsed_line = await self.parse_line(line_as_json)
                    if parsed_line != None:
                        parsed_lines.append(parsed_line)
                except:
                    # print(f"could not parse line {line} \n ... skipping")
                    continue
        # cleanup the alertsfile after parsing to prevent doubled entries
        open(self.alert_file_location, 'w').close()
        return parsed_lines

    async def parse_line(self, line):
        parsed_line = Alert()
        # get available infor from db
        timestamp = line["StartTime"]
        parsed_line.time = datetime.fromisoformat(timestamp).astimezone(timezone.utc).replace(tzinfo=None).isoformat()
        parsed_line.source_ip = line["Source"][0]["IP"]
        parsed_line.source_port = str(line["Source"][0]["Port"][0])
        parsed_line.destination_ip = line["Target"][0]["IP"]
        parsed_line.destination_port = str(line["Target"][0]["Port"][0])
        # only include alerts that have a chance to be matched to the csv files
        # removing them here does nothing, as they youldn be matched anyways and wouldn't affect the statistics besides unassigned_requests 
        if not parsed_line.time or not parsed_line.source_ip or not parsed_line.source_port or not parsed_line.destination_ip or not parsed_line.destination_port:
            raise Exception("Missing important information in logline")
        # get the rest of the information from alerts.json
        parsed_line.message = line["Description"]
        # Slips currently does not support different types
        parsed_line.type = "Alert"

        # parse the nested threat level to a number
        parsed_line.severity = await self.normalize_threat_levels(await self.get_threat_level(line["Severity"]))
        return parsed_line
 
    async def get_threat_level(self, severity: str, ):
        # get everything after substring for threat level
        severity = severity.lower()
        try:
            if severity == "info":
                return 0    
            elif severity == "low":
                return 1
            elif severity == "medium":
                return 2
            elif severity == "high":
                return 3
            elif severity == "critical":
                return 4 
        # As alert lines will not have this info but rather a normal threat_level, use that instead
        except Exception as e:
            print(f"Could not determine threat level for line {severity}, using lowest level now")
            return 0



            
    
    async def normalize_threat_levels(self, threat: int):
        # threat levels are from 0 (info) to 4 (critical)
        # parse the levels into numbers
        max_level = 4
        if threat is None or threat > max_level:
            # Unexpected high value
            return None
        return round(threat / max_level,2)



        
