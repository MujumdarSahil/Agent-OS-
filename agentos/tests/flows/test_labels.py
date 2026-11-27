"""Unit tests for Information Flow Control (IFC) labels and Labeled container."""

import pytest

from agentos.flows.labels import (
    Confidentiality,
    Integrity,
    Label,
    Labeled,
)


def test_label_defaults_and_validation():
    lbl = Label()
    assert lbl.integrity == Integrity.UNTRUSTED.value
    assert lbl.confidentiality == Confidentiality.INTERNAL.value
    assert lbl.sources == frozenset()

    with pytest.raises(ValueError, match="Invalid integrity"):
        Label(integrity="invalid")

    with pytest.raises(ValueError, match="Invalid confidentiality"):
        Label(confidentiality="top_secret")


def test_label_join_integrity():
    t = Label.trusted()
    u = Label.untrusted()

    # trusted + trusted -> trusted
    assert t.join(t).integrity == Integrity.TRUSTED.value

    # trusted + untrusted -> untrusted (untrusted always wins)
    assert t.join(u).integrity == Integrity.UNTRUSTED.value
    assert u.join(t).integrity == Integrity.UNTRUSTED.value
    assert u.join(u).integrity == Integrity.UNTRUSTED.value


def test_label_join_confidentiality_lattice():
    pub = Label.trusted(confidentiality=Confidentiality.PUBLIC.value)
    inter = Label.trusted(confidentiality=Confidentiality.INTERNAL.value)
    conf = Label.trusted(confidentiality=Confidentiality.CONFIDENTIAL.value)
    sec = Label.trusted(confidentiality=Confidentiality.SECRET.value)

    assert pub.join(inter).confidentiality == Confidentiality.INTERNAL.value
    assert inter.join(conf).confidentiality == Confidentiality.CONFIDENTIAL.value
    assert conf.join(sec).confidentiality == Confidentiality.SECRET.value
    assert pub.join(sec).confidentiality == Confidentiality.SECRET.value


def test_label_join_sources_union():
    lbl1 = Label.untrusted(sources={"node_1", "event_1"})
    lbl2 = Label.trusted(sources={"node_2"})

    joined = lbl1.join(lbl2)
    assert joined.sources == frozenset({"node_1", "event_1", "node_2"})
    assert joined.integrity == Integrity.UNTRUSTED.value


def test_labeled_value_wrapper():
    val = Labeled.of("sensitive payload", integrity=Integrity.UNTRUSTED.value, confidentiality=Confidentiality.SECRET.value)
    assert val.unwrap() == "sensitive payload"
    assert val.label.integrity == Integrity.UNTRUSTED.value
    assert val.label.confidentiality == Confidentiality.SECRET.value
