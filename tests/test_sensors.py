from bbh_scanner.resources.sensors import SensorReading, parse_nvidia_smi_temp


def test_parse_single_temp():
    assert parse_nvidia_smi_temp("57\n") == 57.0


def test_parse_first_of_multiple_gpus():
    assert parse_nvidia_smi_temp("57\n61\n") == 57.0


def test_parse_empty():
    assert parse_nvidia_smi_temp("") is None
    assert parse_nvidia_smi_temp("\n\n") is None


def test_parse_non_numeric():
    assert parse_nvidia_smi_temp("N/A\n") is None


def test_hottest():
    assert SensorReading(cpu_temp=70.0, gpu_temp=85.0).hottest() == 85.0
    assert SensorReading(cpu_temp=70.0).hottest() == 70.0
    assert SensorReading().hottest() is None
