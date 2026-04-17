package traffic

import "testing"

func TestMeterSnapshotAndResetTracksDirectionCounters(t *testing.T) {
	meter := NewMeter()

	meter.Add(DirectionUpload, 1500)
	meter.Add(DirectionUpload, 500)
	meter.Add(DirectionDownload, 4096)

	snapshot := meter.SnapshotAndReset()
	if snapshot[DirectionUpload].Bytes != 2000 || snapshot[DirectionUpload].Packets != 2 {
		t.Fatalf("unexpected upload counters: %#v", snapshot[DirectionUpload])
	}
	if snapshot[DirectionDownload].Bytes != 4096 || snapshot[DirectionDownload].Packets != 1 {
		t.Fatalf("unexpected download counters: %#v", snapshot[DirectionDownload])
	}

	next := meter.SnapshotAndReset()
	if next[DirectionUpload].Bytes != 0 || next[DirectionDownload].Bytes != 0 {
		t.Fatalf("expected counters to reset, got %#v", next)
	}
}
