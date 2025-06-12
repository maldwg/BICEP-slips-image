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
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        parser.alert_file_location = temp_file.name
    alerts = await parser.parse_alerts()
    assert alerts == [], "Expected empty list for an empty log file"


@pytest.mark.asyncio
async def test_parse_alerts_valid_and_invalid_data(parser: SlipsParser):
    original_alert_file = f"{TEST_FILE_LOCATION}/alerts.json"
    temporary_alert_file = f"{TEST_FILE_LOCATION}/alerts_temporary.json"
    shutil.copyfile(original_alert_file, temporary_alert_file)
    parser.alert_file_location = temporary_alert_file
    print(parser.alert_file_location)
    alerts = await parser.parse_alerts()
    
    # it is more than there are lines, because the actual flows are in the db.
    # do not get fooled by the json file!
    assert len(alerts) == 121
    alerts = sorted(alerts, key=lambda alert: (alert.time, alert.source_ip))
    assert alerts[0].severity == 0.25

    os.remove(temporary_alert_file)


@pytest.mark.asyncio
async def test_parse_alerts_invalid_data(parser: SlipsParser):
    original_alert_file = f"{TEST_FILE_LOCATION}/invalid_alerts.json"
    temporary_alert_file = f"{TEST_FILE_LOCATION}/alerts_temporary.json"
    shutil.copy(original_alert_file, temporary_alert_file)
    parser.alert_file_location = temporary_alert_file
    print(parser.alert_file_location)
    alerts = await parser.parse_alerts()
    
    assert len(alerts) == 0
    os.remove(temporary_alert_file)


@pytest.mark.asyncio
async def test_normalize_threat_levels(parser: SlipsParser):   
    assert await parser.normalize_threat_levels(1) == 0.25
    assert await parser.normalize_threat_levels(2) == 0.5
    assert await parser.normalize_threat_levels(3) == 0.75
    assert await parser.normalize_threat_levels(4) == 1
    assert await parser.normalize_threat_levels(5) == None
    assert await parser.normalize_threat_levels(None) is None
