package jwtgen

import "time"

type TimeGetter interface {
	GetTime() float64
}

type StdTimeGetter struct{}

func (StdTimeGetter) GetTime() float64 {
	return float64(time.Now().Unix())
}
