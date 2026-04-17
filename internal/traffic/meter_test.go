package traffic

import (
	"net/netip"
	"testing"
)

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

func TestMeterSnapshotAndResetTracksTopConversations(t *testing.T) {
	meter := NewMeter()

	meter.AddPacket(DirectionOther, Packet{
		SrcIP:    mustAddr("2001:db8::10"),
		DstIP:    mustAddr("2001:db8::20"),
		SrcPort:  443,
		DstPort:  53000,
		Protocol: "tcp",
		Bytes:    1200,
	})
	meter.AddPacket(DirectionOther, Packet{
		SrcIP:    mustAddr("2001:db8::10"),
		DstIP:    mustAddr("2001:db8::20"),
		SrcPort:  443,
		DstPort:  53000,
		Protocol: "tcp",
		Bytes:    800,
	})

	snapshot := meter.SnapshotAndResetDetailed(3)
	top := snapshot.Conversations[DirectionOther]
	if len(top) != 1 {
		t.Fatalf("expected 1 top conversation, got %d: %#v", len(top), top)
	}
	if top[0].Bytes != 2000 || top[0].Packets != 2 {
		t.Fatalf("unexpected top counters: %#v", top[0])
	}
	if top[0].Key.SrcIP.String() != "2001:db8::10" || top[0].Key.DstIP.String() != "2001:db8::20" {
		t.Fatalf("unexpected top key: %#v", top[0].Key)
	}
}

func mustAddr(s string) netip.Addr {
	return netip.MustParseAddr(s)
}
