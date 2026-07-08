from bbh_scanner.config import GovernorConfig
from bbh_scanner.resources.governor import Mode, decide
from bbh_scanner.resources.sensors import SensorReading

CFG = GovernorConfig()


def r(**kw) -> SensorReading:
    return SensorReading(**kw)


def test_critical_temp_pauses_even_in_turbo():
    plan = decide(r(cpu_temp=91.0), CFG, override="turbo")
    assert plan.mode is Mode.PAUSED
    assert plan.can_work is False
    assert plan.cooldown_sec == CFG.cooldown_sec


def test_gpu_critical_pauses():
    plan = decide(r(cpu_temp=50.0, gpu_temp=95.0), CFG, override="turbo")
    assert plan.mode is Mode.PAUSED


def test_manual_turbo_uses_full_machine_when_cool():
    plan = decide(r(cpu_temp=55.0, gpu_temp=60.0, cpu_load=90.0), CFG, override="turbo")
    # in turbo il carico utente non conta: solo la temperatura
    assert plan.mode is Mode.TURBO
    assert plan.max_concurrency == CFG.turbo_concurrency


def test_turbo_throttles_down_when_hot_but_not_critical():
    plan = decide(r(cpu_temp=84.0), CFG, override="turbo")  # >=82 hot, <90 crit
    assert plan.mode is Mode.NORMAL
    assert "throttle termico" in plan.reason


def test_override_powersave():
    plan = decide(r(cpu_temp=50.0, cpu_load=5.0), CFG, override="powersave")
    assert plan.mode is Mode.POWERSAVE
    assert plan.max_concurrency == CFG.powersave_concurrency


def test_auto_busy_goes_powersave():
    plan = decide(r(cpu_temp=60.0, cpu_load=50.0), CFG, override="auto")
    assert plan.mode is Mode.POWERSAVE
    assert "in uso" in plan.reason


def test_auto_on_battery_goes_powersave():
    plan = decide(r(cpu_temp=60.0, cpu_load=5.0, on_battery=True), CFG, override="auto")
    assert plan.mode is Mode.POWERSAVE
    assert plan.reason == "batteria"


def test_auto_cool_and_idle_goes_turbo():
    plan = decide(r(cpu_temp=55.0, cpu_load=5.0, on_battery=False), CFG, override="auto")
    assert plan.mode is Mode.TURBO


def test_auto_moderate_is_normal():
    plan = decide(r(cpu_temp=70.0, cpu_load=25.0, on_battery=False), CFG, override="auto")
    assert plan.mode is Mode.NORMAL


def test_auto_hot_goes_powersave():
    plan = decide(r(cpu_temp=86.0, cpu_load=5.0), CFG, override="auto")
    assert plan.mode is Mode.POWERSAVE


def test_governor_disabled_is_normal():
    cfg = GovernorConfig(enabled=False)
    plan = decide(r(cpu_temp=95.0), cfg)  # anche con temp critica, se disabilitato
    assert plan.mode is Mode.NORMAL


def test_unknown_temps_default_reasonably():
    # sensori assenti (None): niente turbo automatico (prudenza), regime NORMAL
    plan = decide(r(cpu_load=5.0), CFG, override="auto")
    assert plan.mode is Mode.NORMAL
