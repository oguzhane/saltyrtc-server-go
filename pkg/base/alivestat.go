package base

type AliveStatType = uint8

const (
	AliveStatActive = 0x00
	AliveStatOrphan = 0x01
	AliveStatDeath  = 0x10
	AliveStatOff    = 0x11
)

func MarkAsOrphan(currStat AliveStatType) AliveStatType {
	if currStat <= AliveStatOrphan {
		return AliveStatOrphan
	}
	return AliveStatOff
}

func MarkAsDeath(currStat AliveStatType) AliveStatType {
	if currStat == AliveStatActive || currStat == AliveStatDeath {
		return AliveStatDeath
	}
	return AliveStatOff
}
