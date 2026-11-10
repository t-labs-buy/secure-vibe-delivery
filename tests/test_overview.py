from secure_vibe_delivery import gate, scoring
from secure_vibe_delivery.models import CheckResult, RunOptions, RunState, Status, SubCheck
from secure_vibe_delivery.report.overview import hero

S = Status


def _sub(i, s):
    return SubCheck(id=i, label=i, status=s)


def _run(sec=S.PASS, tests=S.PASS, load=S.WARN, latency=S.PASS, mode="quick", url="http://x"):
    st = RunState(run_id="t", options=RunOptions(project_path="/p", mode=mode, peak_users=50, target_url=url),
                  state="done", created_at=0)
    st.results = {
        "security": CheckResult(name="security", status=sec, subchecks=[
            _sub("secrets", sec), _sub("code", S.PASS), _sub("own-data", S.WARN), _sub("review", S.WARN)]),
        "functional": CheckResult(name="functional", status=tests, data={"counts": {"total": 48, "passed": 48}},
                                  subchecks=[_sub("tests", tests), _sub("coverage", S.PASS), _sub("wrong-case", S.PASS)]),
        "performance": CheckResult(name="performance", status=S.PASS, data={"users": 75, "aggregate": {"p95": 130.0}},
                                   subchecks=[_sub("load", load), _sub("failures", S.PASS), _sub("latency", latency),
                                              _sub("crashes", S.PASS)]),
    }
    res = gate.ensure_all(st)
    v = gate.verdict(res)
    sc = scoring.compute(res, mode != "gate")
    return hero(st, res, v, sc, gate.must_fix(res)), v


def test_provisional_matches_the_path():
    h, v = _run()
    assert v == "PROVISIONAL" and h["head"][:3] == ("One step from ", "GO", ".")
    assert [g["state"] for g in h["gates"]] == ["done", "done", "done", "pending", "signoff"]
    assert h["gates"][1]["sub"] == "48/48 tests" and h["gates"][2]["sub"] == "p95 130 ms"
    assert h["gates"][3]["sub"] == "15 min · 75 users" and h["cleared"] == 3
    assert "75 users" in h["text"] and h["tested_users"] == 75


def test_gate_mode_go():
    h, v = _run(load=S.PASS, mode="gate")
    assert v == "GO" and h["head"][1] == "GO" and h["gates"][3]["state"] == "done" and h["cleared"] == 4
    assert h["gates"][2]["label"] == "Load test"


def test_no_go_counts_blockers_and_names_failures():
    h, v = _run(sec=S.FAIL, latency=S.FAIL)
    assert v == "NO-GO" and h["head"][3] == "bad"
    assert h["gates"][0]["state"] == "fail" and h["gates"][2]["state"] == "fail"
    assert "Security and quick load failed" in h["text"]


def test_no_url_means_load_did_not_run():
    st = RunState(run_id="t", options=RunOptions(project_path="/p", target_url=None), state="done", created_at=0)
    st.results = {"security": CheckResult(name="security", status=S.PASS, subchecks=[_sub("secrets", S.PASS)]),
                  "performance": CheckResult(name="performance", status=S.NOT_RUN, subchecks=[
                      _sub("load", S.NOT_RUN), _sub("failures", S.NOT_RUN)])}
    res = gate.ensure_all(st)
    h = hero(st, res, gate.verdict(res), scoring.compute(res, True), gate.must_fix(res))
    assert h["gates"][2]["state"] == "notrun" and h["gates"][2]["sub"] == "no test URL given"
    assert h["gates"][3]["state"] == "notrun" and h["tested_users"] is None
    assert "didn't run, which counts as a failure" in h["text"]


def test_score_note_adds_up():
    st = RunState(run_id="t", options=RunOptions(project_path="/p"), state="done", created_at=0)
    score = {"score": 98, "caps": [], "checks": {"functional": {"components": [
        {"label": "Wrong-case tests present", "points": 0.0, "max_points": 2.5},
        {"label": "Tests passing", "points": 97.5, "max_points": 97.5}]}}}
    h = hero(st, {}, "PROVISIONAL", score, [])
    assert h["score_note"] == "2.5 points lost, all of them in “Wrong-case tests present”."


def test_summary_units_cover_every_automated_check():
    h, _ = _run()
    labels = [u["label"] for u in h["units"]]
    assert all(not l.endswith(("own-data", "review")) for l in labels)
    assert h["tally"]["PASS"] + h["tally"]["FAIL"] + h["tally"]["NOT_RUN"] + h["tally"]["WARN"] == len(h["units"])
    assert labels[0].startswith("Security:")
