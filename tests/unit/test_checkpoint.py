"""Unit tests for transfer checkpointing and resumption."""

from peervault.transfer.checkpoint import TransferCheckpoint


def test_checkpoint_fresh_start(tmp_path):
    target = tmp_path / "large.iso"
    cp = TransferCheckpoint(target, "abc123sha", 1000000, 65536)

    assert cp.get_resume_chunk_index() is None


def test_checkpoint_record_and_resume(tmp_path):
    target = tmp_path / "large.iso"
    chunk_size = 100
    cp = TransferCheckpoint(target, "abc123sha", 500, chunk_size)

    # Write dummy part file with 3 chunks
    cp.part_file.write_bytes(b"A" * 300)
    cp.record_chunk(1)
    cp.record_chunk(2)
    cp.record_chunk(3)
    cp.flush_meta()

    # Re-instantiate checkpoint to simulate process restart
    cp2 = TransferCheckpoint(target, "abc123sha", 500, chunk_size)
    assert cp2.get_resume_chunk_index() == 4


def test_checkpoint_finalize(tmp_path):
    target = tmp_path / "final.data"
    cp = TransferCheckpoint(target, "sha999", 200, 100)
    cp.part_file.write_bytes(b"completed data")
    cp.record_chunk(1)
    cp.flush_meta()

    final_path = cp.finalize()
    assert final_path == target
    assert target.is_file()
    assert target.read_bytes() == b"completed data"
    assert not cp.part_file.exists()
    assert not cp.meta_file.exists()
