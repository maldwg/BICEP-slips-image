import json


from abc import ABC, abstractmethod
from datetime import datetime

class IDSParser(ABC):
    timestamp_format = '%Y-%m-%dT%H:%M:%S.%f%z'

    @property
    @abstractmethod
    def alertFileLocation(self):
        pass
    @abstractmethod
    def parse_alerts_from_file(self):
        pass
    @abstractmethod
    def parse_alerts_from_network_traffic(self):
        pass

class Alert():
    """
    Class which contains the most important fields of an alert (one line of anomaly).
    It presents a standardized interface for the different IDS to map their distinct alerts to.
    """
    time: datetime
    source: str
    destination: str
    severity: int
    type: str
    message: str
    def __str__(self):
        return f"{self.time}, From: {self.source}, To: {self.destination}, Type: {self.type}, Content: {self.message}, Severity: {self.severity}"



import json 
from datetime import datetime

class SlipsParser(IDSParser):
    
    alertFileLocation = ""
    def parse_alerts_from_file(self, file_location=alertFileLocation):
        
        parsed_lines = []

        with open(file_location, "r") as file:
            for line in file:
                line_as_json = json.loads(line)
                parsed_lines.append(self.parse_line(line_as_json))
        return parsed_lines
    
    def parse_alerts_from_network_traffic():
        pass

    def parse_line(self, line):
        parsed_line = Alert()
        # todo: check if Is detect time now correctt in slips? --> it is not --> find out if necessary to id or id in other means
        parsed_line.time = datetime.strptime(line.get("DetectTime"), self.timestamp_format) 
        # since it is an array, acces the first element, then get the ip, the result is also in an array
        parsed_line.source = line.get("Source")[0].get("IP4")[0]
        try:
            parsed_line.destination = line.get("Target")[0].get("IP4")[0]
        except TypeError as e:
            # many time there is no target, hence leave the information empty then
            parsed_line.destination = ""
        parsed_line.message = line.get("Attach")[0].get("Content")
        parsed_line.type = line.get("Category")
        parsed_line.severity = line.get("accumulated_threat_level")

        return parsed_line
if __name__ == "__main__":
    parser = SlipsParser()
    res = parser.parse_alerts_from_file("./slips_alerts.json")
    print(str(res[0]))
