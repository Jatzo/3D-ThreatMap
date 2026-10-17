import pytest
from pydantic import ValidationError

from backend.models import AttackEvent
from backend.simulator import AttackSimulator


def an_event() -> dict:
    return AttackSimulator(seed=1).next_event().model_dump(mode="json")


def test_an_event_from_a_dataset_cannot_be_marked_simulated():
    data = an_event() | {"dataset": "Some dataset", "simulated": True}
    with pytest.raises(ValidationError, match="cannot be marked simulated"):
        AttackEvent.model_validate(data)


def test_an_unknown_attack_type_is_refused():
    with pytest.raises(ValidationError, match="unknown attack_type"):
        AttackEvent.model_validate(an_event() | {"attack_type": "constructor"})


def test_an_event_written_before_the_new_fields_still_loads_with_defaults():
    data = an_event()
    for field in ("source", "dataset", "original_ts"):
        data.pop(field)
    event = AttackEvent.model_validate(data)
    assert (event.source, event.dataset, event.original_ts) == ("simulator", None, None)
    assert event.simulated is True


def test_a_source_does_not_need_an_address():
    data = an_event()
    data["src"]["ip"] = None
    assert AttackEvent.model_validate(data).src.ip is None
