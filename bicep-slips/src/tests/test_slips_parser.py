import pytest
import json
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import Response
from src.utils.models.ids_base import Alert
from src.models.slips_parser import SlipsParser
import shutil
import json
import tempfile
from pathlib import Path
import os


TEST_FILE_LOCATION = "bicep-slips/src/tests/testfiles"

@pytest.fixture
def parser():
    parser = SlipsParser()
    parser.alert_file_location = f"{TEST_FILE_LOCATION}/alerts.json"
    parser.database_path = f"{TEST_FILE_LOCATION}/flows.sqlite"
    return parser

@pytest.mark.asyncio
async def test_parse_alerts_empty_file(parser: SlipsParser):
    # necessary to mock the db here, otherwise not able to go though the function understandably
    original_db_file = f"{TEST_FILE_LOCATION}/flows.sqlite"
    temporary_db_file = f"{TEST_FILE_LOCATION}/flows_temporary.sqlite"
    shutil.copyfile(original_db_file, temporary_db_file)
    parser.database_dumper.db_path = temporary_db_file
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        parser.alert_file_location = temp_file.name
    alerts = await parser.parse_alerts()
    assert alerts == [], "Expected empty list for an empty log file"
    os.remove(temporary_db_file)


@pytest.mark.asyncio
async def test_parse_alerts_valid_and_invalid_data(parser: SlipsParser):
    original_alert_file = f"{TEST_FILE_LOCATION}/alerts.json"
    temporary_alert_file = f"{TEST_FILE_LOCATION}/alerts_temporary.json"
    shutil.copyfile(original_alert_file, temporary_alert_file)
    parser.alert_file_location = temporary_alert_file
    original_db_file = f"{TEST_FILE_LOCATION}/flows.sqlite"
    temporary_db_file = f"{TEST_FILE_LOCATION}/flows_temporary.sqlite"
    shutil.copyfile(original_db_file, temporary_db_file)
    parser.database_dumper.db_path = temporary_db_file
    print(parser.alert_file_location)
    alerts = await parser.parse_alerts()
    
    # it is more than there are lines, because the actual flows are in the db.
    # do not get fooled by the json file!
    assert len(alerts) == 507
    assert alerts[0].severity == 0.25

    os.remove(temporary_alert_file)
    os.remove(temporary_db_file)


@pytest.mark.asyncio
async def test_parse_alerts_invalid_data(parser: SlipsParser):
    original_alert_file = f"{TEST_FILE_LOCATION}/invalid_alerts.json"
    temporary_alert_file = f"{TEST_FILE_LOCATION}/alerts_temporary.json"
    shutil.copy(original_alert_file, temporary_alert_file)
    parser.alert_file_location = temporary_alert_file
    original_db_file = f"{TEST_FILE_LOCATION}/flows.sqlite"
    temporary_db_file = f"{TEST_FILE_LOCATION}/flows_temporary.sqlite"
    shutil.copyfile(original_db_file, temporary_db_file)
    parser.database_dumper.db_path = temporary_db_file
    print(parser.alert_file_location)
    alerts = await parser.parse_alerts()
    
    assert len(alerts) == 0
    os.remove(temporary_alert_file)
    os.remove(temporary_db_file)




@pytest.mark.asyncio
async def test_get_threat_levels(parser: SlipsParser): 

    line = {
        "Format": "IDEA0", 
        "ID": "18f2e37d-159e-4271-9284-714a21f83f25", 
        "DetectTime": "2025-02-01T18:59:15.172047+00:00", 
        "EventTime": "2025-02-01T18:59:15.172078+00:00", 
        "Category": ["Recon"], 
        "Confidence": 1.0, 
        "Source": [{"IP4": ["192.168.2.12"]}], 
        "Target": [{"IP4": ["192.168.2.1"]}], 
        "Attach": [{"Content": "Connecting to private IP: 192.168.2.1 on destination port: 67 threat level: info.", "ContentType": "text/plain"}], 
        "ConnCount": 1, 
        "uids": ["Cy0SBw4uNqKUyimg7j"], 
        "accumulated_threat_level": 0, 
        "timewindow": 1
    }

    assert await parser.get_threat_level(line) == 0
    line["Attach"][0]["Content"] = "Connecting to private IP: 192.168.2.1 on destination port: 67 threat level: low."
    assert await parser.get_threat_level(line) == 1
    line["Attach"][0]["Content"] = "Connecting to private IP: 192.168.2.1 on destination port: 67 threat level: medium."
    assert await parser.get_threat_level(line) == 2
    line["Attach"][0]["Content"] = "Connecting to private IP: 192.168.2.1 on destination port: 67 threat level: high."
    assert await parser.get_threat_level(line) == 3
    line["Attach"][0]["Content"] = "Connecting to private IP: 192.168.2.1 on destination port: 67 threat level: critical."
    assert await parser.get_threat_level(line) == 4
    line["Attach"][0]["Content"] = "Connecting to private IP: 192.168.2.1 on destination port: 67 threat level: IVALID."
    assert await parser.get_threat_level(line) == None

@pytest.mark.asyncio
async def test_normalize_threat_levels(parser: SlipsParser):   
    assert await parser.normalize_threat_levels(1) == 0.25
    assert await parser.normalize_threat_levels(2) == 0.5
    assert await parser.normalize_threat_levels(3) == 0.75
    assert await parser.normalize_threat_levels(4) == 1
    assert await parser.normalize_threat_levels(5) == None
    assert await parser.normalize_threat_levels(None) is None
