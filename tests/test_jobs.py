from bbh_scanner.db.store import Store


def _store(tmp_path):
    return Store(tmp_path / "jobs.db")


def test_enqueue_and_dedup(tmp_path):
    store = _store(tmp_path)
    jid = store.enqueue_job("recon_passive", platform="hackerone", program_handle="acme")
    assert jid is not None
    # stesso job queued → dedup, ritorna None
    assert store.enqueue_job("recon_passive", platform="hackerone", program_handle="acme") is None
    assert store.job_counts() == {"queued": 1}


def test_claim_marks_running(tmp_path):
    store = _store(tmp_path)
    store.enqueue_job("recon_passive", platform="hackerone", program_handle="a")
    store.enqueue_job("recon_passive", platform="hackerone", program_handle="b")
    claimed = store.claim_jobs(1)
    assert len(claimed) == 1
    counts = store.job_counts()
    assert counts.get("running") == 1
    assert counts.get("queued") == 1
    assert claimed[0]["attempts"] == 1


def test_priority_order(tmp_path):
    store = _store(tmp_path)
    store.enqueue_job("recon_passive", program_handle="low", priority=0)
    store.enqueue_job("recon_passive", program_handle="high", priority=10)
    claimed = store.claim_jobs(1)
    assert claimed[0]["program_handle"] == "high"


def test_complete_job(tmp_path):
    store = _store(tmp_path)
    store.enqueue_job("recon_passive", program_handle="a")
    job = store.claim_jobs(1)[0]
    store.complete_job(job["id"])
    assert store.job_counts() == {"done": 1}


def test_fail_job_retries_then_fails(tmp_path):
    store = _store(tmp_path)
    store.enqueue_job("recon_passive", program_handle="a")
    # attempt 1 → sotto max_attempts con retry → torna queued
    job = store.claim_jobs(1)[0]
    state = store.fail_job(job["id"], "boom", retry_after_sec=0, max_attempts=2)
    assert state == "queued"
    # attempt 2 → raggiunge max_attempts → failed
    job = store.claim_jobs(1)[0]
    state = store.fail_job(job["id"], "boom", retry_after_sec=0, max_attempts=2)
    assert state == "failed"
    assert store.job_counts().get("failed") == 1


def test_fail_without_retry_marks_failed(tmp_path):
    store = _store(tmp_path)
    store.enqueue_job("recon_passive", program_handle="a")
    job = store.claim_jobs(1)[0]
    assert store.fail_job(job["id"], "boom") == "failed"


def test_requeue_stale_running(tmp_path):
    store = _store(tmp_path)
    store.enqueue_job("recon_passive", program_handle="a")
    store.claim_jobs(1)  # → running
    assert store.job_counts().get("running") == 1
    n = store.requeue_stale_running()
    assert n == 1
    assert store.job_counts().get("queued") == 1
    assert "running" not in store.job_counts()


def test_reenqueue_after_done(tmp_path):
    store = _store(tmp_path)
    jid = store.enqueue_job("recon_passive", program_handle="a")
    store.complete_job(store.claim_jobs(1)[0]["id"])
    # una volta done, un nuovo enqueue è permesso (dedup vale solo su queued/running)
    jid2 = store.enqueue_job("recon_passive", program_handle="a")
    assert jid2 is not None and jid2 != jid


def test_prune_events(tmp_path):
    store = _store(tmp_path)
    store.log_event("INFO", "t", "vecchio")
    # forziamo un ts vecchio
    store.conn.execute("UPDATE events SET ts='2000-01-01T00:00:00+00:00';")
    store.conn.commit()
    store.log_event("INFO", "t", "nuovo")
    pruned = store.prune_events(days=30)
    assert pruned == 1
    assert len(store.recent_events()) == 1
