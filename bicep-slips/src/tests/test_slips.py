import pytest
import shutil
from unittest.mock import AsyncMock, patch, MagicMock
from src.models.slips import Slips

@pytest.fixture
def ids():
    ids = Slips()
    ids.container_id = 123
    ids.tap_interface_name = "tap123"
    ids.configuration_location = "my/config/location"
    ids.log_location = "my/log/location"
    ids.working_dir = "./"
    return ids

@pytest.mark.asyncio
@patch("shutil.move")
@patch("os.mkdir")
async def test_configure(mock_mkdir, mock_shutil, ids: Slips):
    mock_mkdir.return_value = None
    response = await ids.configure("/path/to/config.yaml")
    mock_shutil.assert_called_once_with("/path/to/config.yaml", ids.configuration_location)
    mock_mkdir.assert_called_once_with(ids.log_location)
    assert response == "succesfully configured"


@pytest.mark.asyncio
@patch("shutil.move")
async def test_configure_ruleset(mock_shutil, ids: Slips):
    # This method does nothing and only passes
    await ids.configure_ruleset("/path/to/rules.rules")
    assert True


@pytest.mark.asyncio
@patch("src.models.slips.execute_command_async", new_callable=AsyncMock)
async def test_execute_network_analysis_command(mock_execute_command, ids: Slips):
    mock_execute_command.return_value = 555  
    pid = await ids.execute_network_analysis_command()
    mock_execute_command.assert_called_once_with([
       "./slips.py", "-c", ids.configuration_location, "-i", ids.tap_interface_name, "-o", ids.log_location]
    )
    assert pid == 555



@pytest.mark.asyncio
@patch("src.models.slips.execute_command_async", new_callable=AsyncMock)
async def test_execute_static_analysis_command(mock_execute_command, ids: Slips):
    mock_execute_command.return_value = 777  
    dataset_path = "/path/to/capture.pcap"
    pid = await ids.execute_static_analysis_command(dataset_path)
    mock_execute_command.assert_called_once_with([
        "./slips.py", "-c", ids.configuration_location, "-f", dataset_path, "-o", ids.log_location]
    )
    assert pid == 777