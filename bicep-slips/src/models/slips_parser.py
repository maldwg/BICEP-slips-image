from src.utils.models.ids_base import IDSParser, Alert
import json 
import os 
import os.path
from datetime import datetime, timezone
import re
from .utils import DatabaseDumper
import ast

class SlipsParser(IDSParser):
    database_path = "/opt/logs/flows.sqlite"
    database_dumper = DatabaseDumper(db_path=database_path)
    alert_file_location = "/opt/logs/alerts.json"
    flows_as_hashmap = {}

    async def parse_alerts(self):
        import time
        start = time.time()
        parsed_lines = []   

        if not os.path.isfile(self.alert_file_location) or not os.path.isfile(self.database_path):
            print(f"files not found, took {time.time() - start} seconds")
            return parsed_lines

        recognized_flows = self.database_dumper.return_table_as_dicts()
        print(f"return table as dict {time.time() - start} seconds")
        self.flows_as_hashmap = self.database_dumper.convert_db_entry_to_hashmap(recognized_flows)
        print(f"converted flows took {time.time() - start} seconds")
        with open(self.alert_file_location, "r") as alerts:
            for line in alerts:
                try:
                    line_as_json = json.loads(line)
                except:
                    print(f"could not parse line {line} \n ... skipping")
                    continue
                # at least one flow/request is assigned to the alert/evidence
                uids = line_as_json["uids"]
                for uid in uids:
                    parsed_line = await self.parse_line(line_as_json, uid)
                    if parsed_line != None:
                        parsed_lines.append(parsed_line)


        print(f"finished iterations in {time.time() - start} seconds")
        # erase files content but do not delete the file itself
        open(self.alert_file_location, 'w').close()
        self.database_dumper.cleanup_table()

        print(30*"---")
        print(f"returned lines")
        print(parsed_lines)
        print(f"successfully finished, took {time.time() - start} seconds")
        try:
            print(f"DEBUG: task health: {self.send_alerts_periodically_task}")
        except:
            pass
        return parsed_lines

    async def parse_line(self, line, uid):
        parsed_line = Alert()
        try:
            flow_information_string = self.flows_as_hashmap[uid]
        except:
            print("could not find uid in hashmap")
            print(uid)
            return None
        flow_information = ast.literal_eval(flow_information_string)

        # get available infor from db
        timestamp = flow_information["starttime"]
        parsed_timestamp = datetime.fromtimestamp(timestamp, timezone.utc).replace(tzinfo=None).isoformat()
        source_ip = flow_information["saddr"]
        source_port = str(flow_information["sport"])
        destination_ip = flow_information["daddr"]
        destination_port = str(flow_information["dport"])
        parsed_line.time = parsed_timestamp
        parsed_line.source_ip = source_ip
        parsed_line.source_port = source_port
        parsed_line.destination_ip = destination_ip
        parsed_line.destination_port = destination_port


        # only include alerts that have a chance to be matched to the csv files
        # removing them here does nothing, as they youldn be matched anyways and wouldn't affect the statistics besides unassigned_requests 
        if not parsed_line.time or not parsed_line.source_ip or not parsed_line.source_port or not parsed_line.destination_ip or not parsed_line.destination_port:
            return None

        # get the rest of the information from alerts.json
        parsed_line.message = line.get("Attach")[0].get("Content")
        parsed_line.type = line.get("Category")[0]
        # parse the nested threat level to a number
        parsed_line.severity = await self.normalize_threat_levels(await self.get_threat_level(line))
        print(parsed_line)
        return parsed_line
     
    
    async def normalize_threat_levels(self, threat: int):
        # threat levels are from 0 (info) to 4 (critical)
        # parse the levels into numbers
        max_level = 4
        return round(threat / max_level,2)

    async def get_threat_level(self, line: str, ):
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
            print(f"Could not determine threat level for line {line}, using lowest level now")
            return 0



        
