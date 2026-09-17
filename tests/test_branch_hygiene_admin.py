from scripts.admin.branch_hygiene_admin import classify_branch


def classify(name, **overrides):
    values = {
        "name": name,
        "sha": "a" * 40,
        "default_branch": "main",
        "open_heads": set(),
        "compare_status": "ahead",
        "ahead_by": 10,
        "behind_by": 0,
        "age_hours": 72.0,
        "min_age_hours": 24,
        "include_chatgpt_b": False,
    }
    values.update(overrides)
    return classify_branch(**values)


def test_default_archive_and_backup_are_never_deletable():
    assert classify("main")[1] is False
    assert classify("archive/history")[0] == "historical_archive"
    assert classify("archive/history")[1] is False
    assert classify("backup/safety")[0] == "safety_backup"
    assert classify("backup/safety")[1] is False


def test_open_pull_request_head_is_never_deletable():
    category, deletable, _ = classify("chatgpt-a/live", open_heads={"chatgpt-a/live"})
    assert category == "active_work"
    assert deletable is False


def test_diverged_and_unmerged_branches_fail_closed():
    assert classify("chatgpt-a/diverged", compare_status="diverged", behind_by=2)[1] is False
    assert classify("chatgpt-a/unmerged", compare_status="behind", behind_by=5)[1] is False


def test_recent_merged_branch_obeys_retention_window():
    category, deletable, _ = classify("chatgpt-a/recent", age_hours=23.9)
    assert category == "recent_merged"
    assert deletable is False


def test_aged_merged_chatgpt_a_codex_and_sol_worker_are_candidates():
    for name in ("chatgpt-a/old", "codex/old", "sol-worker/old"):
        category, deletable, _ = classify(name)
        assert category == "safe_merged_candidate"
        assert deletable is True


def test_chatgpt_b_requires_explicit_cross_workstream_opt_in():
    category, deletable, _ = classify("chatgpt-b/old")
    assert category == "merged_retained"
    assert deletable is False
    category, deletable, _ = classify("chatgpt-b/old", include_chatgpt_b=True)
    assert category == "safe_merged_candidate"
    assert deletable is True


def test_unknown_prefix_is_retained_even_when_merged():
    category, deletable, _ = classify("sol-web-messaging-validator")
    assert category == "merged_retained"
    assert deletable is False
